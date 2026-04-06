"""WHOIS / RDAP collector via ipwhois library."""
import json
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, HTTPLookupError


def collect(ip: str) -> dict:
    """Return RDAP data for the given IP. Gracefully handles errors."""
    result = {"source": "whois_rdap", "ip": ip, "error": None, "data": {}}
    try:
        obj = IPWhois(ip)
        raw = obj.lookup_rdap(depth=1)
        result["data"] = {
            "asn":             raw.get("asn"),
            "asn_cidr":        raw.get("asn_cidr"),
            "asn_country_code":raw.get("asn_country_code"),
            "asn_date":        raw.get("asn_date"),
            "asn_description": raw.get("asn_description"),
            "asn_registry":    raw.get("asn_registry"),
            "network": {
                "name":       raw.get("network", {}).get("name"),
                "handle":     raw.get("network", {}).get("handle"),
                "cidr":       raw.get("network", {}).get("cidr"),
                "start_address": raw.get("network", {}).get("start_address"),
                "end_address":   raw.get("network", {}).get("end_address"),
                "country":    raw.get("network", {}).get("country"),
                "type":       raw.get("network", {}).get("type"),
                "remarks":    raw.get("network", {}).get("remarks"),
            },
            "objects": {
                k: {
                    "handle":       v.get("handle"),
                    "roles":        v.get("roles"),
                    "contact": {
                        "name":  v.get("contact", {}).get("name"),
                        "email": v.get("contact", {}).get("email"),
                        "phone": v.get("contact", {}).get("phone"),
                        "address": v.get("contact", {}).get("address"),
                    },
                }
                for k, v in (raw.get("objects") or {}).items()
            },
        }
    except (IPDefinedError, HTTPLookupError, Exception) as e:
        result["error"] = str(e)
    return result
