import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { AlertTriangle, Check, CheckCircle2, Copy, Info, Loader2, X, XCircle } from "lucide-react";

/* ------------------------------------------------------------------ data hooks */
export function useLoad(fn, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const reload = useCallback(() => {
    setLoading(true);
    return fn()
      .then((d) => { setData(d); setError(null); return d; })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { reload(); }, [reload]);
  return { data, error, loading, reload };
}

export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const toast = useToast();
  const run = async (fn, { success } = {}) => {
    setBusy(true);
    setError(null);
    try {
      const r = await fn();
      if (success) toast({ tone: "ok", title: typeof success === "function" ? success(r) : success });
      return r;
    } catch (e) {
      setError(e.message);
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run, setError };
}

/* ------------------------------------------------------------------ toasts */
const ToastCtx = createContext(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const push = useCallback((t) => {
    const id = Math.random().toString(36).slice(2);
    setItems((xs) => [...xs, { id, ...t }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), t.duration || 4000);
  }, []);
  const icon = { ok: CheckCircle2, bad: XCircle, warn: AlertTriangle, info: Info };
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-5 right-5 z-[60] flex w-80 flex-col gap-2">
        {items.map((t) => {
          const I = icon[t.tone || "info"];
          return (
            <div key={t.id} className="pointer-events-auto flex animate-rise gap-3 rounded-lg border border-line bg-surface p-3 shadow-pop">
              <I className={`mt-0.5 h-4 w-4 shrink-0 text-${t.tone || "info"}`} />
              <div className="min-w-0 text-[13px]">
                <div className="font-medium text-fg">{t.title}</div>
                {t.body && <div className="mt-0.5 text-muted">{t.body}</div>}
              </div>
            </div>
          );
        })}
      </div>
    </ToastCtx.Provider>
  );
}

/* ------------------------------------------------------------------ primitives */
const BTN = {
  primary: "bg-accent text-accent-fg hover:bg-accent/90 shadow-sm",
  secondary: "border border-line-strong bg-surface text-fg hover:bg-inset shadow-sm",
  ghost: "text-muted hover:bg-inset hover:text-fg",
  danger: "border border-bad/30 bg-bad/10 text-bad hover:bg-bad/15",
};
const SIZE = { sm: "h-8 px-2.5 text-[12.5px]", md: "h-9 px-3.5 text-[13px]", lg: "h-10 px-4 text-sm" };

export function Button({ variant = "secondary", size = "md", icon: I, busy, className = "", children, ...rest }) {
  return (
    <button
      className={`inline-flex shrink-0 items-center justify-center gap-2 rounded-lg font-medium transition focus:outline-none focus-visible:ring-[3px] focus-visible:ring-accent/30 disabled:cursor-not-allowed disabled:opacity-50 ${BTN[variant]} ${SIZE[size]} ${className}`}
      disabled={busy || rest.disabled}
      {...rest}
    >
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : I && <I className="h-4 w-4" />}
      {children}
    </button>
  );
}

const TONES = {
  ok: "bg-ok/10 text-ok ring-ok/20",
  bad: "bg-bad/10 text-bad ring-bad/20",
  warn: "bg-warn/10 text-warn ring-warn/25",
  info: "bg-info/10 text-info ring-info/20",
  accent: "bg-accent/10 text-accent ring-accent/20",
  mute: "bg-inset text-muted ring-line-strong",
};

export function Badge({ tone = "mute", dot, children, className = "" }) {
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-2 py-0.5 text-[11.5px] font-medium ring-1 ring-inset ${TONES[tone]} ${className}`}>
      {dot && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}

export function Spinner({ className = "h-4 w-4" }) {
  return <Loader2 className={`animate-spin text-subtle ${className}`} />;
}

export function Alert({ tone = "bad", title, children, className = "" }) {
  const I = { ok: CheckCircle2, bad: XCircle, warn: AlertTriangle, info: Info }[tone];
  return (
    <div className={`flex gap-3 rounded-lg border px-3.5 py-3 text-[13px] ${
      { ok: "border-ok/25 bg-ok/5", bad: "border-bad/25 bg-bad/5", warn: "border-warn/30 bg-warn/5", info: "border-info/25 bg-info/5" }[tone]} ${className}`}>
      <I className={`mt-0.5 h-4 w-4 shrink-0 text-${tone}`} />
      <div className="min-w-0">
        {title && <div className="font-medium text-fg">{title}</div>}
        {children && <div className={title ? "mt-0.5 text-muted" : "text-fg"}>{children}</div>}
      </div>
    </div>
  );
}

export function ErrorBox({ error, className }) {
  return error ? <Alert tone="bad" className={className}>{error}</Alert> : null;
}

export function Field({ label, hint, children }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[12.5px] font-medium text-fg">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-[12px] text-subtle">{hint}</span>}
    </label>
  );
}

export function Card({ title, subtitle, actions, children, className = "", pad = true }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-3.5">
          <div>
            <h2 className="section-title">{title}</h2>
            {subtitle && <p className="mt-0.5 text-[12.5px] text-subtle">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={pad ? "p-5" : ""}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, icon: I, hint, tone = "accent" }) {
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between">
        <span className="text-[12.5px] font-medium text-muted">{label}</span>
        {I && <span className={`flex h-7 w-7 items-center justify-center rounded-md bg-${tone}/10 text-${tone}`}><I className="h-4 w-4" /></span>}
      </div>
      <div className="mt-2 text-[26px] font-semibold leading-none tracking-tight tabular-nums">{value}</div>
      {hint && <div className="mt-1.5 text-[12px] text-subtle">{hint}</div>}
    </div>
  );
}

export function Empty({ icon: I, title, children, action }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      {I && <span className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-inset text-subtle ring-1 ring-line"><I className="h-5 w-5" /></span>}
      <div className="font-medium text-fg">{title}</div>
      {children && <div className="mt-1 max-w-sm text-[13px] text-subtle">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Hash({ value, n = 12, full = false, className = "" }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-subtle">—</span>;
  const copy = (e) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(value).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); });
  };
  return (
    <span className={`group inline-flex max-w-full items-center gap-1 font-mono text-[12px] text-muted ${className}`} title={value}>
      <span className={full ? "break-all" : "truncate"}>{full || value.length <= n + 2 ? value : `${value.slice(0, n)}…`}</span>
      <button onClick={copy} className="shrink-0 rounded p-0.5 text-subtle opacity-0 transition hover:bg-inset hover:text-fg group-hover:opacity-100" aria-label="Copy">
        {copied ? <Check className="h-3 w-3 text-ok" /> : <Copy className="h-3 w-3" />}
      </button>
    </span>
  );
}

export function KV({ rows, cols = 1 }) {
  return (
    <dl className={`grid gap-x-8 gap-y-3 ${cols === 2 ? "sm:grid-cols-2" : ""}`}>
      {rows.filter(Boolean).map(([k, v]) => (
        <div key={k} className="min-w-0">
          <dt className="text-[12px] text-subtle">{k}</dt>
          <dd className="mt-0.5 min-w-0 break-words text-[13px] text-fg">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function CheckRow({ ok, label, detail }) {
  return (
    <div className="flex items-start gap-3 py-2">
      {ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-bad" />}
      <div className="min-w-0">
        <div className="text-[13px] text-fg">{label}</div>
        {detail && <div className="mt-0.5 truncate font-mono text-[11.5px] text-subtle">{detail}</div>}
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions, eyebrow }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <div className="eyebrow mb-1.5">{eyebrow}</div>}
        <h1 className="text-[22px] font-semibold tracking-tight text-fg">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-[13.5px] leading-relaxed text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Tabs({ value, onChange, items }) {
  return (
    <div className="inline-flex rounded-lg border border-line bg-inset p-0.5">
      {items.map(([k, label, count]) => (
        <button key={k} onClick={() => onChange(k)}
          className={`inline-flex h-7 items-center gap-1.5 rounded-md px-3 text-[12.5px] font-medium transition ${value === k ? "bg-surface text-fg shadow-card" : "text-subtle hover:text-fg"}`}>
          {label}{count != null && <span className="tabular-nums text-subtle">{count}</span>}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ overlays */
function useEscape(onClose) {
  useEffect(() => {
    const h = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
}

export function Modal({ open, onClose, title, subtitle, children, footer, width = "max-w-lg" }) {
  useEscape(onClose);
  const ref = useRef(null);
  useEffect(() => { if (open) ref.current?.querySelector("input,select,textarea")?.focus(); }, [open]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4 pt-[10vh] backdrop-blur-[2px] animate-fade-in" onMouseDown={onClose}>
      <div ref={ref} className={`w-full ${width} animate-rise rounded-xl border border-line bg-surface shadow-pop`} onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
          <div>
            <h3 className="text-[15px] font-semibold text-fg">{title}</h3>
            {subtitle && <p className="mt-0.5 text-[12.5px] text-subtle">{subtitle}</p>}
          </div>
          <button onClick={onClose} className="rounded-md p-1 text-subtle hover:bg-inset hover:text-fg"><X className="h-4 w-4" /></button>
        </div>
        <div className="px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 rounded-b-xl border-t border-line bg-inset px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}

export function Drawer({ open, onClose, title, subtitle, children, actions }) {
  useEscape(onClose);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/30 animate-fade-in" onMouseDown={onClose}>
      <aside className="flex h-full w-full max-w-xl animate-slide-in flex-col border-l border-line bg-surface shadow-pop" onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-4 border-b border-line px-6 py-4">
          <div className="min-w-0">
            <h3 className="truncate text-[15px] font-semibold text-fg">{title}</h3>
            {subtitle && <div className="mt-0.5 text-[12.5px] text-subtle">{subtitle}</div>}
          </div>
          <div className="flex items-center gap-2">
            {actions}
            <button onClick={onClose} className="rounded-md p-1 text-subtle hover:bg-inset hover:text-fg"><X className="h-4 w-4" /></button>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
      </aside>
    </div>
  );
}

export function Confirm({ open, onClose, onConfirm, title, children, confirmLabel = "Confirm", danger, busy }) {
  return (
    <Modal open={open} onClose={onClose} title={title} width="max-w-md"
      footer={<>
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button variant={danger ? "danger" : "primary"} busy={busy} onClick={onConfirm}>{confirmLabel}</Button>
      </>}>
      <div className="text-[13.5px] text-muted">{children}</div>
    </Modal>
  );
}

export function Table({ head, children, className = "" }) {
  return (
    <div className={`overflow-x-auto ${className}`}>
      <table className="w-full border-separate border-spacing-0 text-[13px]">
        <thead><tr>{head.map((h, i) => <th key={i} className={`th ${h?.className || ""}`}>{h?.label ?? h}</th>)}</tr></thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
