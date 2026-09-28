# Multi-stage image: build the React UI, then run the FastAPI backend that serves it.
# Railway detects this Dockerfile and skips Railpack's auto-detection entirely.

# ---------- stage 1: frontend build ----------
FROM node:20-alpine AS ui
WORKDIR /ui
# The UI build never runs Electron; skip its postinstall binary download
ENV ELECTRON_SKIP_BINARY_DOWNLOAD=1
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- stage 2: backend runtime ----------
FROM python:3.11-slim AS runtime
WORKDIR /app/backend

# System deps: libglib2.0 is required by opencv-python-headless on slim images
RUN apt-get update \
    && apt-get install -y --no-install-recommends libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY --from=ui /ui/dist /app/frontend/dist

# Data dir (SQLite DB, tokens, blobs) lives on a mounted volume so state
# survives redeploys. Can be configured with SIH_DATA_DIR.
ENV SIH_DATA_DIR=/data \
    SIH_PORT=8765 \
    PYTHONUNBUFFERED=1
VOLUME /data

EXPOSE 8765
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${SIH_PORT}"]
