from __future__ import annotations

from flask import url_for


def build_openapi_spec() -> dict:
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "DomainTools Agent API",
            "version": "1.0.0",
            "description": (
                "Machine-readable API for AI agents and automation. "
                "Provides DNS, WHOIS, GeoIP, reverse DNS, and domain report lookups."
            ),
        },
        "servers": [{"url": "/api/v1"}],
        "paths": {
            "/": {
                "get": {
                    "summary": "API index",
                    "operationId": "apiIndex",
                    "responses": {"200": {"description": "Service metadata and endpoint list"}},
                }
            },
            "/dns": {
                "get": {
                    "summary": "DNS lookup",
                    "operationId": "dnsLookup",
                    "parameters": [
                        {"name": "domain", "in": "query", "required": True, "schema": {"type": "string"}},
                        {
                            "name": "types",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"},
                            "description": "Comma-separated record types (default: A,AAAA,CNAME,MX,NS,TXT,SOA). Use ALL for all supported types.",
                        },
                    ],
                    "responses": {"200": {"description": "DNS records"}, "400": {"description": "Invalid input"}},
                }
            },
            "/whois": {
                "get": {
                    "summary": "WHOIS lookup",
                    "operationId": "whoisLookup",
                    "parameters": [
                        {"name": "domain", "in": "query", "required": True, "schema": {"type": "string"}},
                    ],
                    "responses": {"200": {"description": "WHOIS data"}, "400": {"description": "Invalid input"}},
                }
            },
            "/geo": {
                "get": {
                    "summary": "GeoIP / ASN lookup",
                    "operationId": "geoLookup",
                    "parameters": [
                        {"name": "query", "in": "query", "required": True, "schema": {"type": "string"}, "description": "IP address or domain"},
                    ],
                    "responses": {"200": {"description": "Geo data"}, "400": {"description": "Invalid input"}},
                }
            },
            "/reverse": {
                "get": {
                    "summary": "Reverse DNS (PTR + FCrDNS)",
                    "operationId": "reverseLookup",
                    "parameters": [
                        {"name": "query", "in": "query", "required": True, "schema": {"type": "string"}, "description": "IP address or domain"},
                    ],
                    "responses": {"200": {"description": "Reverse DNS data"}, "400": {"description": "Invalid input"}},
                }
            },
            "/report": {
                "get": {
                    "summary": "Synchronous domain report (DNS + WHOIS + Geo + Reverse)",
                    "operationId": "reportSync",
                    "parameters": [
                        {"name": "domain", "in": "query", "required": False, "schema": {"type": "string"}},
                        {"name": "domains", "in": "query", "required": False, "schema": {"type": "string"}, "description": "Comma-separated domains (max batch size applies)"},
                    ],
                    "responses": {"200": {"description": "Report payload"}, "400": {"description": "Invalid input"}, "429": {"description": "Rate limited"}},
                },
                "post": {
                    "summary": "Queue async domain report job",
                    "operationId": "reportAsync",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "domains": {"type": "array", "items": {"type": "string"}},
                                        "domain": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"202": {"description": "Job queued"}, "400": {"description": "Invalid input"}, "429": {"description": "Rate limited"}},
                },
            },
            "/report/jobs/{job_id}": {
                "get": {
                    "summary": "Poll async report job status",
                    "operationId": "reportJobStatus",
                    "parameters": [
                        {"name": "job_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    ],
                    "responses": {"200": {"description": "Job status"}, "404": {"description": "Job not found"}},
                }
            },
        },
        "components": {
            "securitySchemes": {
                "ApiKeyHeader": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "Required. Set AGENT_API_ENABLED=1 and AGENT_API_KEY on the server, then send the key in this header.",
                }
            }
        },
        "security": [{"ApiKeyHeader": []}],
        "externalDocs": {
            "description": "llms.txt — agent-oriented site description",
            "url": url_for("llms_txt", _external=True),
        },
    }