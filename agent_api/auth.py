from flask import current_app, request


def verify_agent_api_access() -> tuple[bool, str | None]:
    """Return (ok, error_message)."""
    if not current_app.config.get("AGENT_API_ENABLED", False):
        return False, "Agent API is disabled."

    expected = (current_app.config.get("AGENT_API_KEY") or "").strip()
    if not expected:
        return False, "Agent API is enabled but AGENT_API_KEY is not configured."

    provided = (
        (request.headers.get("X-API-Key") or "")
        or (request.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
    ).strip()

    if not provided or provided != expected:
        return False, "Invalid or missing API key."
    return True, None