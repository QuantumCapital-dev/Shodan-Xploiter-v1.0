"""IPInfo.io collector — geolocation, ASN, abuse, hosting detection."""
import requests


IPINFO_URL = "https://ipinfo.io/{ip}/json"


def collect(ip: str, token: str = "") -> dict:
    """Query ipinfo.io. token='' uses the free unauthenticated tier (50k req/mo)."""
    result = {"source": "ipinfo", "ip": ip, "error": None, "data": {}}
    try:
        params = {"token": token} if token else {}
        resp = requests.get(IPINFO_URL.format(ip=ip), params=params, timeout=10)
        resp.raise_for_status()
        raw = resp.json()
        result["data"] = {
            "hostname":   raw.get("hostname"),
            "city":       raw.get("city"),
            "region":     raw.get("region"),
            "country":    raw.get("country"),
            "loc":        raw.get("loc"),        # "lat,lon"
            "org":        raw.get("org"),         # "AS15169 Google LLC"
            "postal":     raw.get("postal"),
            "timezone":   raw.get("timezone"),
            "anycast":    raw.get("anycast", False),
            # Fields available with paid token:
            "abuse":      raw.get("abuse", {}),
            "privacy": raw.get("privacy", {}),   # vpn, proxy, tor, relay, hosting
            "company":    raw.get("company", {}),
            "domains":    raw.get("domains", {}),
        }
    except Exception as e:
        result["error"] = str(e)
    return result
