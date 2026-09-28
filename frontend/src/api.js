// The backend serves the UI itself in production (Electron and container deploys),
// so use same-origin there. Only the Vite dev server (5173) must target the local
// backend on 8765 explicitly. A hardcoded loopback URL would break any hosted deploy.
const BASE = window.location.port === "5173" ? "http://127.0.0.1:8765" : "";
const KEY = "sih.session";

let session = null;
try { session = JSON.parse(sessionStorage.getItem(KEY) || "null"); } catch { session = null; }
const listeners = new Set();

export const auth = {
  get: () => session,
  set(s) {
    session = s;
    try { s ? sessionStorage.setItem(KEY, JSON.stringify(s)) : sessionStorage.removeItem(KEY); } catch { /* ignore */ }
    listeners.forEach((fn) => fn(s));
  },
  subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
};

export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

async function request(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (session?.token) headers.Authorization = `Bearer ${session.token}`;
  const res = await fetch(BASE + path, { ...opts, headers });
  if (res.status === 401 && session?.token && !path.startsWith("/api/auth/login")) {
    auth.set(null); // expired or revoked session -> back to login
  }
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = await res.json();
      msg = Array.isArray(body.detail) ? body.detail.map((d) => d.msg).join("; ") : body.detail || msg;
    } catch { /* not JSON */ }
    throw new ApiError(msg, res.status);
  }
  return res;
}

export const api = {
  get: (p) => request(p).then((r) => r.json()),
  post: (p, json) =>
    request(p, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: json === undefined ? "{}" : JSON.stringify(json),
    }).then((r) => r.json()),
  upload: (p, fields) => {
    const fd = new FormData();
    Object.entries(fields).forEach(([k, v]) => fd.append(k, v));
    return request(p, { method: "POST", body: fd }).then((r) => r.json());
  },
  blob: (p) => request(p).then((r) => r.blob()),
  async download(p, filename) {
    const blob = await api.blob(p);
    saveBlob(blob, filename);
  },
};

export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export const short = (h, n = 10) => (h ? `${h.slice(0, n)}…` : "—");
export const when = (iso) =>
  iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";
export const ago = (iso) => {
  if (!iso) return "—";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.max(s, 0)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};

export const ROLE_LABEL = { "security-officer": "Security Officer", examiner: "Forensic Examiner", auditor: "Auditor" };
