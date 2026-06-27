import os
import sys

if not (os.environ.get("SECRET_KEY") or "").strip():
    sys.stderr.write(
        "ERROR: SECRET_KEY is not set. "
        "Create /etc/domaintools/domaintools.env from deploy/domaintools.env.example.\n"
    )
    raise SystemExit(1)

from app import app

if __name__ == "__main__":
    app.run()