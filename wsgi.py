import os

if not (os.environ.get("SECRET_KEY") or "").strip():
    raise RuntimeError(
        "ERROR: SECRET_KEY is not set. "
        "Create /etc/default/python-domaintools or export SECRET_KEY before starting gunicorn."
    )

from app import app  # noqa: E402
