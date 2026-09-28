# Multi-stage image: build the React UI, then run the FastAPI backend that serves it.
# Railway detects this Dockerfile and skips Railpack's auto-detection entirely.

# ---------- stage 1: frontend build ----------
FROM node:20-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- stage 2: backend runtime ----------
FROM python:3.11-slim AS runtime
WORKDIR /app/backend

# System deps: nothing exotic needed; keep image small
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
