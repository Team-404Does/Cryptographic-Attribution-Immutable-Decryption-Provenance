"""Runtime configuration. Everything lives in a local data directory - no network services."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(os.environ.get("SIH_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
TOKENS_DIR = DATA_DIR / "tokens"
BLOBS_DIR = DATA_DIR / "blobs"
REPORTS_DIR = DATA_DIR / "reports"
NODES_DIR = DATA_DIR / "nodes"
DB_PATH = DATA_DIR / "sih.db"

# Internal stakeholders operating ledger nodes, and the k-of-n admission quorum
LEDGER_NODES = ("legal", "it-security", "compliance")
LEDGER_QUORUM = 2
MAX_PIN_ATTEMPTS = 5

# Demo mode enables seed/reset/tamper helpers, keeps recipient copies on disk for the
# robustness lab and leak simulator. Never enable it on a real installation.
DEMO_MODE = os.environ.get("SIH_DEMO", "").lower() in ("1", "true", "yes")

OPERATOR_SESSION_TTL = 30 * 60      # idle timeout for officer / examiner / auditor logins (s)
DOWNLOAD_TTL = 10 * 60              # how long a freshly decrypted copy can be fetched (s)
MAX_PDF_PAGES = 100                 # refuse larger PDFs (render cost / decompression bombs)
MAX_IMAGE_PIXELS = 60_000_000

# Browser hardening for the loopback API: only these Host headers are served (defeats DNS
# rebinding) and state-changing requests from any other Origin are refused (defeats CSRF).
PORT = int(os.environ.get("SIH_PORT", "8765"))
DEV_MODE = os.environ.get("SIH_DEV", "").lower() in ("1", "true", "yes")   # allows the Vite dev server
ALLOWED_HOSTS = [h for h in os.environ.get("SIH_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",") if h]
ALLOWED_ORIGINS = [f"http://{h}:{PORT}" for h in ("127.0.0.1", "localhost")] + (
    ["http://localhost:5173", "http://127.0.0.1:5173"] if DEV_MODE else [])

# Public deployment (e.g. Railway/Render behind a proxy): SIH_PUBLIC_URL is the origin the
# UI is served from (scheme + host, no trailing slash). When set, that host joins the host
# allow-list and the URL joins the allowed origins so same-origin POSTs keep working.
PUBLIC_URL = os.environ.get("SIH_PUBLIC_URL", "").rstrip("/")
if PUBLIC_URL:
    from urllib.parse import urlsplit
    _p = urlsplit(PUBLIC_URL)
    if _p.hostname:
        ALLOWED_HOSTS.append(_p.hostname)
        ALLOWED_ORIGINS.append(f"{_p.scheme}://{_p.hostname}")
        if _p.port:
            ALLOWED_ORIGINS[-1] = f"{_p.scheme}://{_p.hostname}:{_p.port}"

# Railway injects RAILWAY_PUBLIC_DOMAIN automatically once a public domain is attached,
# so a Railway deploy is allow-listed with zero extra configuration.
RAILWAY_DOMAIN = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip()
if RAILWAY_DOMAIN and RAILWAY_DOMAIN not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append(RAILWAY_DOMAIN)
    ALLOWED_ORIGINS.append(f"https://{RAILWAY_DOMAIN}")


def ensure_dirs() -> None:
    for d in (DATA_DIR, TOKENS_DIR, BLOBS_DIR, REPORTS_DIR, NODES_DIR):
        d.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def master_secret() -> bytes:
    """Installation secret: protects system tokens and derives the watermark embedding key.
    In production this lives inside an HSM; here it is a 0600 file in the data directory."""
    ensure_dirs()
    path = DATA_DIR / "master.key"
    if not path.exists():
        path.write_bytes(os.urandom(32))
        path.chmod(0o600)
    return path.read_bytes()


def reset_caches() -> None:
    master_secret.cache_clear()
