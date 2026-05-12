import os
import socket
import ipaddress
from typing import List, Dict, Optional, Collection, Tuple
from urllib.parse import urljoin, urlparse

import idna
import requests

# Попробуем dnspython (для MX)
try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except Exception:
    HAVE_DNSPYTHON = False


_SITE_CHECKER_UA = "DomainTools-SiteChecker/1.0"
_MAX_REDIRECTS = int(os.getenv("SITE_CHECKER_MAX_REDIRECTS", "5"))
_MAX_HTTP_BYTES = int(os.getenv("SITE_CHECKER_MAX_HTTP_BYTES", "65536"))


def to_punycode(domain: str) -> str:
    d = (domain or "").strip().rstrip(".")
    try:
        return idna.encode(d, uts46=True).decode("ascii")
    except Exception:
        return d


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except Exception:
        return False


def _resolve_public_ips(domain: str) -> Tuple[List[str], Optional[str]]:
    d = to_punycode(domain)
    try:
        infos = socket.getaddrinfo(d, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return [], "DNS resolution failed"

    ips: List[str] = []
    for _, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    public_ips = [ip for ip in ips if _is_public_ip(ip)]
    if not public_ips:
        return [], "Resolved host does not have a public IP."
    return public_ips, None


def _validate_safe_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return "Invalid URL"
    if parsed.scheme.lower() not in {"http", "https"}:
        return "Only HTTP and HTTPS URLs are allowed."
    if not parsed.hostname:
        return "Invalid URL"
    _, err = _resolve_public_ips(parsed.hostname)
    return err


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
    current_url = url

    try:
        for _ in range(max(0, _MAX_REDIRECTS) + 1):
            url_err = _validate_safe_url(current_url)
            if url_err:
                result["error"] = url_err
                result["url"] = current_url
                return result

            try:
                r = requests.head(
                    current_url,
                    allow_redirects=False,
                    timeout=timeout,
                    headers={"User-Agent": _SITE_CHECKER_UA},
                )
            except Exception:
                r = requests.get(
                    current_url,
                    allow_redirects=False,
                    timeout=timeout,
                    stream=True,
                    headers={"User-Agent": _SITE_CHECKER_UA},
                )
                # Drain only a tiny bounded part so the connection can close cleanly.
                read = 0
                for chunk in r.iter_content(chunk_size=8192):
                    read += len(chunk or b"")
                    if read >= max(1024, _MAX_HTTP_BYTES):
                        break

            result["http_code"] = r.status_code
            result["url"] = r.url
            if r.is_redirect or r.is_permanent_redirect:
                location = r.headers.get("Location")
                if location:
                    current_url = urljoin(current_url, location)
                    continue
            return result

        result["error"] = "Too many redirects."
        result["url"] = current_url
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def ip_info_for_domain(domain: str) -> Dict[str, Optional[str]]:
    public_ips, err = _resolve_public_ips(domain)
    if err or not public_ips:
        return {"ip": None, "org": None, "country": None, "city": None, "error": err or "DNS resolution failed"}
    ip = public_ips[0]

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


def is_in_rkn(domain: str, cached_domains: Optional[Collection[str]]) -> Optional[bool]:
    if not cached_domains:
        return None
    d = to_punycode(domain).lower()
    return d in cached_domains
