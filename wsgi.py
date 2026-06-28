import os
import sys

# Gunicorn systemd unit sets PATH to the venv only; whois(1) lives in /usr/bin.
_path = os.environ.get("PATH", "")
for _entry in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"):
    if _entry not in _path.split(os.pathsep):
        _path = f"{_path}{os.pathsep}{_entry}" if _path else _entry
os.environ["PATH"] = _path

if not (os.environ.get("SECRET_KEY") or "").strip():
    sys.stderr.write(
        "ERROR: SECRET_KEY is not set. "
        "Create /etc/domaintools/domaintools.env from deploy/domaintools.env.example.\n"
    )
    raise SystemExit(1)

from app import app

if __name__ == "__main__":
    app.run()