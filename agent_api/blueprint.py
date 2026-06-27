from __future__ import annotations

import re
from typing import List

from flask import Blueprint, current_app, jsonify, request, url_for

from .auth import verify_agent_api_access
from .openapi import build_openapi_spec
from . import services

agent_api_bp = Blueprint("agent_api", __name__, url_prefix="/api/v1")


def _client_ip() -> str:
    import app as app_module
    return app_module._client_ip()


def _rate_limited(endpoint: str, limit_config_key: str, default_limit: int) -> bool:
    import app as app_module
    limit = int(current_app.config.get(limit_config_key, default_limit))
    return app_module._endpoint_ip_rate_limited(endpoint, _client_ip(), limit)


def _guard(*, rate_endpoint: str = "agent_api", rate_limit_key: str = "AGENT_API_RATE_LIMIT_PER_MIN", rate_default: int = 30):
    ok, err = verify_agent_api_access()
    if not ok:
        return jsonify(ok=False, error=err), 403
    if _rate_limited(rate_endpoint, rate_limit_key, rate_default):
        return jsonify(ok=False, error="Rate limit exceeded. Try again later."), 429
    return None


def _parse_domains_from_request() -> tuple[List[str] | None, str | None]:
    import app as app_module

    payload = request.get_json(silent=True) or {}
    raw = (
        payload.get("domains")
        or request.values.get("domains")
        or request.values.get("domain")
        or payload.get("domain")
        or ""
    )
    if isinstance(raw, list):
        items = [str(x).strip() for x in raw if str(x).strip()]
    else:
        items = [x for x in re.split(r"[\s,;]+", str(raw)) if x.strip()]

    uniq = [x for x in dict.fromkeys(items)]
    if not uniq:
        return None, "At least one domain is required."
    max_batch = int(current_app.config.get("REPORT_MAX_BATCH", app_module.REPORT_MAX_BATCH))
    if len(uniq) > max_batch:
        return None, f"Too many domains in batch (max {max_batch})."

    normalized: List[str] = []
    for item in uniq:
        host_ascii, err = app_module._normalize_domain_query(item)
        if err or not host_ascii:
            return None, err or "Invalid domain name."
        normalized.append(host_ascii)
    return normalized, None


@agent_api_bp.get("/")
def api_index():
    blocked = _guard()
    if blocked:
        return blocked
    return jsonify(
        ok=True,
        name="DomainTools Agent API",
        version="1.0.0",
        openapi=url_for("agent_api.openapi_spec", _external=True),
        llms_txt=url_for("llms_txt", _external=True),
        endpoints={
            "dns": url_for("agent_api.api_dns", _external=True),
            "whois": url_for("agent_api.api_whois", _external=True),
            "geo": url_for("agent_api.api_geo", _external=True),
            "reverse": url_for("agent_api.api_reverse", _external=True),
            "report": url_for("agent_api.api_report", _external=True),
        },
        auth={
            "api_key_required": True,
            "headers": ["X-API-Key", "Authorization: Bearer <key>"],
        },
    ), 200


@agent_api_bp.get("/openapi.json")
def openapi_spec():
    blocked = _guard()
    if blocked:
        return blocked
    return jsonify(build_openapi_spec()), 200


@agent_api_bp.get("/dns")
def api_dns():
    blocked = _guard()
    if blocked:
        return blocked

    domain = (request.args.get("domain") or request.args.get("q") or "").strip()
    if not domain:
        return jsonify(ok=False, error="Parameter 'domain' is required."), 400

    raw_types = [t.strip() for t in (request.args.get("types") or "").split(",") if t.strip()]
    try:
        data = services.lookup_dns(domain, raw_types or None)
        return jsonify(ok=True, data=data), 200
    except Exception as exc:
        return jsonify(ok=False, error=str(exc)), 400


@agent_api_bp.get("/whois")
def api_whois():
    blocked = _guard()
    if blocked:
        return blocked

    domain = (request.args.get("domain") or request.args.get("q") or "").strip()
    if not domain:
        return jsonify(ok=False, error="Parameter 'domain' is required."), 400
    try:
        data = services.lookup_whois(domain)
        return jsonify(ok=True, data=data), 200
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    except Exception:
        current_app.logger.exception("Agent API WHOIS error")
        return jsonify(ok=False, error="WHOIS lookup failed."), 500


@agent_api_bp.get("/geo")
def api_geo():
    blocked = _guard()
    if blocked:
        return blocked

    query = (request.args.get("query") or request.args.get("q") or "").strip()
    if not query:
        return jsonify(ok=False, error="Parameter 'query' is required."), 400
    try:
        data = services.lookup_geo(query)
        return jsonify(ok=True, data=data), 200
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    except Exception:
        current_app.logger.exception("Agent API Geo error")
        return jsonify(ok=False, error="Geo lookup failed."), 500


@agent_api_bp.get("/reverse")
def api_reverse():
    blocked = _guard()
    if blocked:
        return blocked

    query = (request.args.get("query") or request.args.get("q") or "").strip()
    if not query:
        return jsonify(ok=False, error="Parameter 'query' is required."), 400
    try:
        data = services.lookup_reverse(query)
        return jsonify(ok=True, data=data), 200
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    except Exception:
        current_app.logger.exception("Agent API reverse error")
        return jsonify(ok=False, error="Reverse lookup failed."), 500


@agent_api_bp.route("/report", methods=["GET", "POST"])
def api_report():
    blocked = _guard(
        rate_endpoint="agent_api_report",
        rate_limit_key="AGENT_API_REPORT_RATE_LIMIT_PER_MIN",
        rate_default=10,
    )
    if blocked:
        return blocked

    domains, err = _parse_domains_from_request()
    if err:
        return jsonify(ok=False, error=err), 400
    assert domains is not None

    source_input = ",".join(domains)

    if request.method == "POST" and request.args.get("async", "").lower() in {"1", "true", "yes"}:
        job_id = services.queue_report_job(domains, source_input)
        if not job_id:
            return jsonify(ok=False, error="Report job storage unavailable."), 503
        return jsonify(
            ok=True,
            status="queued",
            job_id=job_id,
            poll_url=url_for("agent_api.api_report_job", job_id=job_id, _external=True),
        ), 202

    if request.method == "POST":
        job_id = services.queue_report_job(domains, source_input)
        if not job_id:
            return jsonify(ok=False, error="Report job storage unavailable."), 503
        return jsonify(
            ok=True,
            status="queued",
            job_id=job_id,
            poll_url=url_for("agent_api.api_report_job", job_id=job_id, _external=True),
        ), 202

    try:
        reports = services.build_report(domains, source_input)
        return jsonify(ok=True, data={"domains": domains, "reports": reports}), 200
    except Exception:
        current_app.logger.exception("Agent API report error")
        return jsonify(ok=False, error="Report build failed."), 500


@agent_api_bp.get("/report/jobs/<job_id>")
def api_report_job(job_id: str):
    blocked = _guard(
        rate_endpoint="agent_api_report",
        rate_limit_key="AGENT_API_REPORT_RATE_LIMIT_PER_MIN",
        rate_default=10,
    )
    if blocked:
        return blocked

    job = services.get_report_job(job_id)
    if not job:
        return jsonify(ok=False, error="not_found"), 404

    status = str(job.get("status") or "queued").lower()
    payload = {
        "ok": True,
        "job_id": job_id,
        "status": status,
        "domains": job.get("domains") or [],
        "source_input": job.get("source_input"),
    }
    if status == "done":
        payload["reports"] = job.get("reports") or []
    elif status == "failed":
        payload["error"] = job.get("error")
    return jsonify(payload), 200