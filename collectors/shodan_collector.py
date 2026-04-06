"""
Shodan collector — unified API + web-scraper fallback.

Strategy:
  1. Try Shodan official API (requires SHODAN_API_KEY, no query credits).
  2. If API fails for ANY reason (403, no key, network error, etc.)
     fall back to passive web scraping of https://www.shodan.io/host/<ip>.
  3. Both paths return the SAME output schema so the rest of the pipeline
     (main.py, prompts.py, report_writer.py) never needs to branch.

Output schema (result["data"]):
  ip, hostnames, domains, country_code, country_name, city, region_code,
  org, isp, asn, ports, os, tags, last_update, services[]
    └─ port, transport, product, version, cpe, banner,
       timestamp, ssl, vulns[], vuln_details{}
  all_cves_found[]          ← scraped CVEs (empty when via API)
  source_method             ← "api" | "web_scraper"

result["fallback"] = True when the scraper was used.
"""

import re
import time
import requests
from bs4 import BeautifulSoup

# ── optional official SDK ──────────────────────────────────────
try:
    import shodan as shodan_lib
    from shodan.exception import APIError as ShodanAPIError
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    ShodanAPIError = Exception          # dummy so bare except still works


# ══════════════════════════════════════════════════════════════
#  WEB SCRAPER  (passive, no API key required)
# ══════════════════════════════════════════════════════════════

_SHODAN_HOST_URL = "https://www.shodan.io/host/{ip}"

_SCRAPER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux aarch64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection":      "keep-alive",
    "DNT":             "1",
}


def _clean(text: str) -> str:
    return " ".join(text.split()).strip() if text else ""


def _scrape_general_info(text: str) -> dict:
    """Parse the General Information block from page text."""
    info = {"country": "", "city": "", "org": "", "isp": "", "asn": "", "os": ""}

    m = re.search(r"General Information(.+?)(?:Open Ports|Last Seen|Tags:|$)", text, re.S)
    if not m:
        return info

    block = _clean(m.group(1))

    fields = [
        ("country", r"Country\s+(.+?)(?=City|Organization|ISP|ASN|Operating System|$)"),
        ("city",    r"City\s+(.+?)(?=Country|Organization|ISP|ASN|Operating System|$)"),
        ("org",     r"Organization\s+(.+?)(?=Country|City|ISP|ASN|Operating System|$)"),
        ("isp",     r"ISP\s+(.+?)(?=Country|City|Organization|ASN|Operating System|$)"),
        ("asn",     r"ASN\s+(AS\d+)"),
        ("os",      r"Operating System\s+(.+?)(?=Country|City|Organization|ISP|ASN|$)"),
    ]
    for key, pattern in fields:
        match = re.search(pattern, block, re.I)
        if match:
            info[key] = _clean(match.group(1))

    return info


def _scrape_open_ports(text: str) -> list:
    """Return sorted list of open port ints."""
    # Stop at first "port / proto" service block
    m = re.search(r"Open Ports\s+([\s\S]+?)(?=\d{1,5}\s*/\s*(?:tcp|udp))", text)
    if not m:
        m = re.search(r"Open Ports\s+([\d\s]+?)(?=[A-Za-z]{4,}|$)", text)
    if not m:
        return []
    raw = m.group(1)
    return sorted({int(p) for p in re.findall(r"\d+", raw) if 1 <= int(p) <= 65535})


def _scrape_tags(text: str) -> list:
    m = re.search(r"Tags:\s*(.+?)(?=General Information|Open Ports|$)", text)
    if not m:
        return []
    return [t.strip() for t in _clean(m.group(1)).split() if t.strip()]


def _scrape_last_seen(text: str) -> str:
    m = re.search(r"Last Seen:\s*(\d{4}-\d{2}-\d{2})", text)
    return m.group(1) if m else ""


def _scrape_services(text: str, ports: list) -> list:
    """Extract per-port service blocks."""
    services = []
    for port in ports:
        svc = {
            "port":      port,
            "transport": "tcp",
            "product":   None,
            "banner":    None,
            "vulns":     [],
            "ssl":       False,
        }
        pattern = re.compile(
            rf"{port}\s*/\s*(tcp|udp)([\s\S]+?)(?=\d{{1,5}}\s*/\s*(?:tcp|udp)|$)"
        )
        m = pattern.search(text)
        if m:
            svc["transport"] = m.group(1)
            block = _clean(m.group(2))[:800]
            svc["banner"] = block

            cve_list     = re.findall(r"CVE-\d{4}-\d{4,7}", block, re.I)
            svc["vulns"] = sorted(set(cve_list))

            if "ssl certificate" in block.lower() or "tls" in block.lower():
                svc["ssl"] = True

            low = block.lower()
            if   "ssh"           in low: svc["product"] = "ssh"
            elif "redis"         in low: svc["product"] = "redis"
            elif "mongodb"       in low: svc["product"] = "mongodb"
            elif "elasticsearch" in low: svc["product"] = "elasticsearch"
            elif "mysql"         in low: svc["product"] = "mysql"
            elif "postgres"      in low: svc["product"] = "postgresql"
            elif "rdp"           in low: svc["product"] = "rdp"
            elif "ftp"           in low: svc["product"] = "ftp"
            elif "smtp"          in low: svc["product"] = "smtp"
            elif "sip"           in low: svc["product"] = "sip"
            elif "http"          in low: svc["product"] = "http"

            server_m = re.search(r"Server:\s*(\S{1,60})", block)
            if server_m and not svc["product"]:
                svc["product"] = _clean(server_m.group(1))

        services.append(svc)
    return services


def _normalize_scraper_services(raw_services: list) -> list:
    """
    Align scraper service dicts to the same schema as the API collector
    so the rest of the pipeline never needs to branch on source.
    """
    normalized = []
    for s in raw_services:
        normalized.append({
            "port":        s["port"],
            "transport":   s["transport"],
            "product":     s["product"],
            "version":     None,          # not available via scraping
            "cpe":         [],
            "banner":      s["banner"],
            "timestamp":   None,
            # Keep ssl as a simple flag string so main.py display works
            "ssl":         "self-signed" if s["ssl"] else None,
            "vulns":       s["vulns"],    # already a list of CVE strings
            "vuln_details": {             # minimal stub for each found CVE
                cve: {"cvss": None, "summary": "", "references": []}
                for cve in s["vulns"]
            },
        })
    return normalized


def _collect_via_scraper(ip: str) -> dict:
    """
    Scrape https://www.shodan.io/host/<ip> and return a result dict
    whose ["data"] matches the API collector schema.
    """
    result = {
        "source":        "shodan_web",
        "source_method": "web_scraper",
        "fallback":      True,
        "ip":            ip,
        "url":           _SHODAN_HOST_URL.format(ip=ip),
        "error":         None,
        "data":          {},
    }

    try:
        resp = requests.get(
            _SHODAN_HOST_URL.format(ip=ip),
            headers=_SCRAPER_HEADERS,
            timeout=20,
        )

        if resp.status_code == 404:
            result["error"] = "IP not found in Shodan database (404)"
            return result
        if resp.status_code != 200:
            result["error"] = f"Scraper HTTP {resp.status_code}"
            return result

        soup      = BeautifulSoup(resp.text, "html.parser")
        page_text = soup.get_text(" ", strip=True)
        raw_text  = _clean(page_text)

        low = raw_text.lower()
        if "404: not found" in low or "no information available" in low:
            result["error"] = "IP not found in Shodan database"
            return result

        general   = _scrape_general_info(raw_text)
        ports     = _scrape_open_ports(raw_text)
        tags      = _scrape_tags(raw_text)
        last_seen = _scrape_last_seen(raw_text)
        raw_svcs  = _scrape_services(raw_text, ports)
        services  = _normalize_scraper_services(raw_svcs)
        all_cves  = sorted({c for c in re.findall(r"CVE-\d{4}-\d{4,7}", page_text, re.I)})

        result["data"] = {
            # ── identity (normalized to API schema) ──
            "ip":           ip,
            "hostnames":    [],           # not available via scraping
            "domains":      [],
            "country_code": "",
            "country_name": general["country"],
            "city":         general["city"],
            "region_code":  "",
            "org":          general["org"],
            "isp":          general["isp"],
            "asn":          general["asn"],
            "os":           general["os"] or None,
            "tags":         tags,
            "last_update":  last_seen,    # same key as API output
            # ── surface ──
            "ports":        ports,
            "services":     services,
            # ── extra scraper-only fields ──
            "all_cves_found": all_cves,
            "raw_excerpt":    raw_text[:3000],
        }

    except requests.exceptions.Timeout:
        result["error"] = "Scraper request timed out (20s)"
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"Scraper connection error: {exc}"
    except Exception as exc:
        result["error"] = f"Scraper parse error: {exc}"

    return result


# ══════════════════════════════════════════════════════════════
#  OFFICIAL API  (uses shodan SDK, no query credits on any plan)
# ══════════════════════════════════════════════════════════════

def _collect_via_api(ip: str, api_key: str) -> dict:
    result = {
        "source":        "shodan",
        "source_method": "api",
        "fallback":      False,
        "ip":            ip,
        "error":         None,
        "data":          {},
    }

    if not _SDK_AVAILABLE:
        result["error"] = "shodan SDK not installed (pip install shodan)"
        return result

    try:
        api = shodan_lib.Shodan(api_key)
        raw = api.host(ip)

        services = []
        for item in raw.get("data", []):
            ssl_subject = None
            if item.get("ssl"):
                ssl_subject = (
                    item["ssl"].get("cert", {}).get("subject")
                    or item["ssl"].get("cert", {}).get("subject_dn")
                )
            vuln_map = item.get("vulns") or {}
            services.append({
                "port":      item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product":   item.get("product"),
                "version":   item.get("version"),
                "cpe":       item.get("cpe", []),
                "banner":    (item.get("data") or "")[:500],
                "timestamp": item.get("timestamp"),
                "ssl":       ssl_subject,
                "vulns":     list(vuln_map.keys()),
                "vuln_details": {
                    k: {
                        "cvss":       v.get("cvss"),
                        "summary":    v.get("summary", "")[:300],
                        "references": v.get("references", [])[:3],
                    }
                    for k, v in vuln_map.items()
                },
            })

        result["data"] = {
            "ip":           raw.get("ip_str"),
            "hostnames":    raw.get("hostnames", []),
            "domains":      raw.get("domains", []),
            "country_code": raw.get("country_code"),
            "country_name": raw.get("country_name"),
            "city":         raw.get("city"),
            "region_code":  raw.get("region_code"),
            "org":          raw.get("org"),
            "isp":          raw.get("isp"),
            "asn":          raw.get("asn"),
            "ports":        raw.get("ports", []),
            "os":           raw.get("os"),
            "tags":         raw.get("tags", []),
            "last_update":  raw.get("last_update"),
            "services":     services,
            # keep consistent with scraper schema
            "all_cves_found": [],
        }

    except ShodanAPIError as exc:
        result["error"] = f"Shodan API error: {exc}"
    except Exception as exc:
        result["error"] = str(exc)

    return result


# ══════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════

def collect(ip: str, api_key: str = "") -> dict:
    """
    Collect Shodan data for *ip*.

    Priority:
      1. Official API  — if api_key is set and call succeeds.
      2. Web scraper   — automatic fallback on ANY API failure,
                         or when api_key is empty/missing.

    Returns a unified result dict; caller checks result["error"] as usual.
    result["fallback"]      → True  when scraper was used
    result["source_method"] → "api" | "web_scraper"
    """
    # ── Try API first if key is available ──────────────────────
    if api_key:
        api_result = _collect_via_api(ip, api_key)
        if not api_result["error"]:
            return api_result
        # API failed — store original error, fall through to scraper
        api_error = api_result["error"]
    else:
        api_error = "no API key configured"

    # ── Fallback: passive web scraper ──────────────────────────
    scraper_result = _collect_via_scraper(ip)

    # Attach the original API error so main.py can log both
    scraper_result["api_error"] = api_error

    return scraper_result
