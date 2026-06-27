"""Thin service layer reusing core DomainTools logic from app.py."""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional

import dns.reversename
import dns.resolver
import idna
import whois
from ipwhois import IPWhois


def _app():
    import app as app_module
    return app_module


DNS_TYPE_OPTIONS = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "PTR", "NAPTR",
    "TLSA", "SSHFP", "DS", "DNSKEY", "CDS", "CDNSKEY", "SPF", "HTTPS", "SVCB", "LOC",
    "RP", "HINFO", "CERT", "DNAME", "URI",
]
DEFAULT_DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


def _normalize_types(raw_types: List[str] | None) -> List[str]:
    selected = [t.strip().upper() for t in (raw_types or []) if t and t.strip()]
    if not selected:
        selected = list(DEFAULT_DNS_TYPES)
    if "ALL" in selected:
        selected = list(DNS_TYPE_OPTIONS)
    return [t for t in selected if t in DNS_TYPE_OPTIONS] or list(DEFAULT_DNS_TYPES)


def lookup_dns(domain: str, types: List[str] | None = None) -> Dict[str, object]:
    m = _app()
    query = (domain or "").strip()
    if not query.isascii():
        query = idna.encode(query, uts46=True).decode("ascii")
    m.validate_domain(query)

    selected_types = _normalize_types(types)
    records: Dict[str, List[str]] = {}

    def fetch(rtype: str):
        try:
            answers = dns.resolver.resolve(query, rtype)
            vals = []
            for r in answers:
                if rtype == "MX":
                    vals.append(f"{getattr(r, 'preference', '')} {str(getattr(r, 'exchange', '')).rstrip('.')}".strip())
                elif rtype == "SOA":
                    vals.append(
                        f"{str(getattr(r, 'mname', '')).rstrip('.')} {str(getattr(r, 'rname', '')).rstrip('.')} "
                        f"{getattr(r, 'serial', '')} {getattr(r, 'refresh', '')} {getattr(r, 'retry', '')} "
                        f"{getattr(r, 'expire', '')} {getattr(r, 'minimum', '')}"
                    )
                elif rtype == "SRV":
                    vals.append(
                        f"{getattr(r, 'priority', '')} {getattr(r, 'weight', '')} {getattr(r, 'port', '')} "
                        f"{str(getattr(r, 'target', '')).rstrip('.')}"
                    )
                elif rtype == "CAA":
                    vals.append(f"{getattr(r, 'flags', '')} {getattr(r, 'tag', '')} {getattr(r, 'value', '')}".strip())
                elif rtype in {"DS", "CDS"}:
                    vals.append(
                        f"{getattr(r, 'key_tag', '')} {getattr(r, 'algorithm', '')} {getattr(r, 'digest_type', '')} {getattr(r, 'digest', '')}"
                    )
                elif rtype in {"DNSKEY", "CDNSKEY"}:
                    vals.append(
                        f"{getattr(r, 'flags', '')} {getattr(r, 'protocol', '')} {getattr(r, 'algorithm', '')} {getattr(r, 'key', '')}"
                    )
                elif rtype == "TXT":
                    chunks = getattr(r, "strings", None)
                    if chunks:
                        vals.append("".join(ch.decode("utf-8", errors="ignore") if isinstance(ch, bytes) else str(ch) for ch in chunks))
                    else:
                        vals.append(str(r).rstrip("."))
                else:
                    vals.append(str(r).rstrip("."))
            if vals:
                records[rtype] = vals
        except Exception:
            pass

    for rt in selected_types:
        fetch(rt)

    m._track_domain_for_seo(query)
    return {"domain": query, "types": selected_types, "has_records": bool(records), "records": records}


def lookup_whois(domain: str) -> Dict[str, object]:
    m = _app()
    q, err = m._normalize_domain_query(domain)
    if err or not q:
        raise ValueError(err or "Invalid domain name.")

    def _compute_whois():
        base: Dict[str, object] = {}
        maybe_text = m._whois_call(["whois", "-H", q], timeout=12)
        important = False
        try:
            w = whois.whois(q)
            for k, v in w.__dict__.items():
                if k.startswith("_"):
                    continue
                base[k] = v
            important = True
        except Exception:
            pass

        if maybe_text and not important:
            parsed = m._parse_ru_whois_text(maybe_text) or m.parse_whois_text(q, maybe_text)
            base.update(parsed)

        base.setdefault("domain_name", q)
        du = m._to_unicode(q)
        if du and du != q:
            base["domain_unicode"] = du
        return base

    data = m.cache_json(f"cache:whois:{q}", 300, _compute_whois)
    m._track_domain_for_seo(q)
    return data


def lookup_geo(query: str) -> Dict[str, object]:
    m = _app()
    q, err = m._normalize_domain_query(query)
    if err or not q:
        raise ValueError(err or "Invalid query.")

    try:
        ipaddress.ip_address(q)
        ip = q
    except Exception:
        ips = []
        try:
            for rr in dns.resolver.resolve(q, "A"):
                ips.append(rr.to_text())
        except Exception:
            pass
        try:
            for rr in dns.resolver.resolve(q, "AAAA"):
                ips.append(rr.to_text())
        except Exception:
            pass
        ip = ips[0] if ips else None

    if not ip:
        raise ValueError("No IPs found for the host.")

    def _compute_geo():
        ipw = IPWhois(ip)
        who = ipw.lookup_rdap()
        country_code = (who.get("asn_country_code") or "").upper()
        country_name = who.get("network", {}).get("country", "") or country_code
        return {
            "ip": ip,
            "asn": who.get("asn"),
            "country_code": country_code,
            "country_name": country_name,
        }

    result = m.cache_json(f"cache:geo:{ip}", 300, _compute_geo)
    m._track_domain_for_seo(q)
    return result


def lookup_reverse(query: str) -> Dict[str, object]:
    m = _app()

    def _resolve_host_ips(host: str) -> dict:
        out = {}
        for t in ("A", "AAAA"):
            try:
                answers = dns.resolver.resolve(host, t)
                out[t] = [str(r) for r in answers]
            except Exception:
                pass
        return out

    def _reverse_one_ip(ip: str) -> dict:
        row = {"ip": ip, "ptr": [], "fcrdns_ok": False, "forward_of_ptr": {}}
        try:
            rev = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev, "PTR")
            ptrs = [str(r).rstrip(".") for r in answers]
            row["ptr"] = ptrs

            forward_addrs = set()
            for hn in ptrs:
                ips = _resolve_host_ips(hn)
                row["forward_of_ptr"][hn] = ips
                forward_addrs.update(ips.get("A", []))
                forward_addrs.update(ips.get("AAAA", []))

            row["fcrdns_ok"] = ip in forward_addrs
        except Exception as e:
            row["error"] = str(e)
        return row

    q = (query or "").strip()
    try:
        ipaddress.ip_address(q)
        is_ip = True
    except Exception:
        is_ip = False

    if is_ip:
        def _compute_reverse_ip():
            row = _reverse_one_ip(q)
            return {"input": q, "type": "ip", "rows": [row]}

        return m.cache_json(f"cache:reverse:{q}", 300, _compute_reverse_ip)

    qnorm, qerr = m._normalize_domain_query(q)
    if qerr or not qnorm:
        raise ValueError(qerr or "Invalid query.")
    host_ascii = qnorm

    def _compute_reverse_host():
        fwd = _resolve_host_ips(host_ascii)
        rows = []
        for ip in sorted(set((fwd.get("A") or []) + (fwd.get("AAAA") or []))):
            rows.append(_reverse_one_ip(ip))
        return {"input": q, "input_ascii": host_ascii, "type": "host", "forward": fwd, "rows": rows}

    result = m.cache_json(f"cache:reverse:{host_ascii}", 300, _compute_reverse_host)
    m._track_domain_for_seo(host_ascii)
    return result


def build_report(domains: List[str], source_input: str) -> List[Dict[str, object]]:
    m = _app()
    reports = []
    for d in domains:
        report = m.cache_json(
            f"cache:report:full:{d}",
            m.REPORT_FULL_TTL_S,
            lambda d=d: m._build_domain_report(d, source_input),
        )
        whois_block = (report or {}).get("whois") if isinstance(report, dict) else {}
        whois_missing_core = any(
            not (whois_block or {}).get(k)
            for k in ("registrar", "creation_date", "expiration_date")
        )
        if whois_missing_core:
            report = m._build_domain_report(d, source_input)
        reports.append(report)
        m._track_domain_for_seo(d)
    return reports


def queue_report_job(domains: List[str], source_input: str) -> Optional[str]:
    import uuid

    m = _app()
    job_id = uuid.uuid4().hex
    if not m._save_report_job(job_id, {"status": "queued", "domains": domains, "source_input": source_input}):
        return None
    m._REPORT_ASYNC_POOL.submit(m._execute_report_job, job_id, domains, source_input)
    return job_id


def get_report_job(job_id: str) -> Optional[Dict[str, object]]:
    m = _app()
    if not m._is_valid_report_job_id(job_id):
        return None
    return m._load_report_job(job_id)