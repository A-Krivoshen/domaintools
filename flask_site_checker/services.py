import os
import socket
from typing import List, Dict, Optional

import idna
import requests

# Попробуем dnspython (для MX)
try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except Exception:
    HAVE_DNSPYTHON = False


def to_punycode(domain: str) -> str:
    d = (domain or "").strip().rstrip(".")
    try:
        return idna.encode(d, uts46=True).decode("ascii")
    except Exception:
        return d


def resolve_dns(domain: str) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    d = to_punycode(domain)

    # A/AAAA
    try:
        infos = socket.getaddrinfo(d, None, proto=socket.IPPROTO_TCP)
        seen = set()
        for _, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip in seen:
                continue
            seen.add(ip)
            if ":" in ip:
                records.append({"type": "AAAA", "ipv6": ip})
            else:
                records.append({"type": "A", "ip": ip})
    except Exception:
        pass

    # MX
    if HAVE_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(d, "MX", lifetime=3.0)
            for r in answers:
                records.append({
                    "type": "MX",
                    "target": str(r.exchange).rstrip("."),
                    "pri": int(getattr(r, "preference", 0)),
                })
        except Exception:
            pass

    return records


def http_check(domain: str, timeout: float = 10.0) -> Dict[str, Optional[str]]:
    d = to_punycode(domain)
    url = f"https://{d}"
    result: Dict[str, Optional[str]] = {"http_code": 0, "url": url, "error": None}
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout)
        result["http_code"] = r.status_code
        result["url"] = r.url
        return result
    except Exception as e:
        try:
            r = requests.get(url, allow_redirects=True, timeout=timeout, stream=True)
            result["http_code"] = r.status_code
            result["url"] = r.url
            return result
        except Exception as e2:
            result["error"] = str(e2) or str(e)
            return result


def ip_info_for_domain(domain: str) -> Dict[str, Optional[str]]:
    d = to_punycode(domain)
    try:
        ip = socket.gethostbyname(d)
    except Exception:
        return {"ip": None, "org": None, "country": None, "city": None, "error": "DNS resolution failed"}

    token = os.getenv("IPINFO_TOKEN", "").strip()
    url = f"https://ipinfo.io/{ip}/json" + (f"?token={token}" if token else "")
    try:
        resp = requests.get(url, timeout=8)
        data = resp.json() if resp.ok else {}
        return {
            "ip": ip,
            "org": data.get("org"),
            "country": data.get("country"),
            "city": data.get("city"),
            "error": None,
        }
    except Exception as e:
        return {"ip": ip, "org": None, "country": None, "city": None, "error": str(e)}


def rkn_domain_list(fetcher=requests.get) -> list:
    url = "https://reestr.rublacklist.net/api/v3/domains/"
    try:
        r = fetcher(url, timeout=12)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("domains"), list):
            return data["domains"]
    except Exception:
        pass
    return []


def is_in_rkn(domain: str, cached_list: Optional[list]) -> Optional[bool]:
    if not cached_list:
        return None
    d = to_punycode(domain).lower()
    return d in {x.lower() for x in cached_list if isinstance(x, str)}
