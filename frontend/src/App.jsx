import React, { useEffect, useState } from "react";
import {
  Activity, BadgeCheck, ChevronDown, FileLock2, FlaskConical, Gauge, KeyRound, Link2, LogOut, Moon,
  ScanSearch, ScrollText, ShieldCheck, Sun, UserCog, Users,
} from "lucide-react";
import { api, auth, ROLE_LABEL } from "./api.js";
import { Badge, ToastProvider, useLoad } from "./components/ui.jsx";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Recipients from "./pages/Recipients.jsx";
import Operators from "./pages/Operators.jsx";
import Documents from "./pages/Documents.jsx";
import Sessions from "./pages/Sessions.jsx";
import Ledger from "./pages/Ledger.jsx";
import Forensics from "./pages/Forensics.jsx";
import Reports from "./pages/Reports.jsx";
import Robustness from "./pages/Robustness.jsx";
import Viewer from "./pages/Viewer.jsx";

const ALL = ["security-officer", "examiner", "auditor"];
const NAV = [
  { group: "Overview", items: [
    { id: "dashboard", label: "Dashboard", icon: Gauge, roles: ALL, C: Dashboard },
  ] },
  { group: "Identity & access", items: [
    { id: "recipients", label: "Recipients", icon: Users, roles: ALL, C: Recipients },
    { id: "operators", label: "Operators", icon: UserCog, roles: ["security-officer"], C: Operators },
    { id: "documents", label: "Documents", icon: FileLock2, roles: ALL, C: Documents },
  ] },
  { group: "Assurance", items: [
    { id: "sessions", label: "Decryption log", icon: Activity, roles: ALL, C: Sessions },
    { id: "ledger", label: "Audit ledger", icon: Link2, roles: ALL, C: Ledger },
  ] },
  { group: "Forensics", items: [
    { id: "forensics", label: "Leak analysis", icon: ScanSearch, roles: ["examiner"], C: Forensics },
    { id: "reports", label: "Evidence reports", icon: ScrollText, roles: ["examiner"], C: Reports },
    { id: "robustness", label: "Robustness lab", icon: FlaskConical, roles: ["examiner"], demo: true, C: Robustness },
  ] },
];

function useRoute() {
  const read = () => window.location.hash.replace(/^#\/?/, "") || "dashboard";
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const h = () => setRoute(read());
    window.addEventListener("hashchange", h);
    return () => window.removeEventListener("hashchange", h);
  }, []);
  return [route, (r) => { window.location.hash = `/${r}`; }];
}

function useTheme() {
  const initial = () => {
    try { const t = localStorage.getItem("sih.theme"); if (t) return t; } catch { /* ignore */ }
    return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
  };
  const [theme, setTheme] = useState(initial);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("sih.theme", theme); } catch { /* ignore */ }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

function useSession() {
  const [s, setS] = useState(auth.get());
  useEffect(() => auth.subscribe(setS), []);
  return s;
}

function Brand() {
  return (
    <div className="flex items-center gap-2.5">
      <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent text-accent-fg shadow-sm">
        <ShieldCheck className="h-[18px] w-[18px]" />
      </span>
      <div className="leading-tight">
        <div className="text-[13.5px] font-semibold text-fg">Provenance Console</div>
        <div className="text-[11px] text-subtle">PQC leak attribution</div>
      </div>
    </div>
  );
}

function ThemeButton({ theme, toggle }) {
  return (
    <button onClick={toggle} className="flex h-8 w-8 items-center justify-center rounded-lg text-muted hover:bg-inset hover:text-fg" title="Toggle theme">
      {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}

function UserMenu({ session, onLogout }) {
  const [open, setOpen] = useState(false);
  const op = session.operator;
  const initials = op.name.split(" ").map((p) => p[0]).slice(0, 2).join("");
  return (
    <div className="relative">
      <button onClick={() => setOpen((o) => !o)} className="flex items-center gap-2.5 rounded-lg py-1 pl-1 pr-2 hover:bg-inset">
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-accent/15 text-[11.5px] font-semibold text-accent">{initials}</span>
        <span className="hidden text-left leading-tight sm:block">
          <span className="block text-[12.5px] font-medium text-fg">{op.name}</span>
          <span className="block text-[11px] text-subtle">{ROLE_LABEL[op.role]}</span>
        </span>
        <ChevronDown className="h-3.5 w-3.5 text-subtle" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-30" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-40 mt-1.5 w-64 animate-rise rounded-xl border border-line bg-surface p-1.5 shadow-pop">
            <div className="px-3 py-2">
              <div className="text-[13px] font-medium text-fg">{op.name}</div>
              <div className="mt-0.5 font-mono text-[11px] text-subtle">{op.id}</div>
              <div className="mt-2 flex items-center gap-1.5 text-[11.5px] text-subtle"><BadgeCheck className="h-3.5 w-3.5 text-ok" /> ML-DSA token session · 30 min idle timeout</div>
            </div>
            <div className="my-1 border-t border-line" />
            <button onClick={onLogout} className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-[13px] text-fg hover:bg-inset">
              <LogOut className="h-4 w-4 text-subtle" /> Sign out and lock token
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function Console({ session, status, reloadStatus, theme, toggleTheme }) {
  const [route, go] = useRoute();
  const role = session.operator.role;
  const visible = NAV.map((g) => ({ ...g, items: g.items.filter((i) => i.roles.includes(role) && (!i.demo || status?.demo_mode)) }))
    .filter((g) => g.items.length);
  const flat = visible.flatMap((g) => g.items);
  const current = flat.find((i) => i.id === route) || flat[0];
  const C = current.C;

  const logout = async () => {
    try { await api.post("/api/auth/logout"); } catch { /* already expired */ }
    auth.set(null);
  };

  return (
    <div className="flex h-full">
      <aside className="flex w-[232px] shrink-0 flex-col border-r border-line bg-surface">
        <div className="flex h-14 items-center border-b border-line px-4"><Brand /></div>
        <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
          {visible.map((g) => (
            <div key={g.group}>
              <div className="eyebrow mb-1.5 px-2">{g.group}</div>
              <div className="space-y-0.5">
                {g.items.map((n) => {
                  const active = n.id === current.id;
                  return (
                    <button key={n.id} onClick={() => go(n.id)}
                      className={`flex h-8 w-full items-center gap-2.5 rounded-lg px-2 text-[13px] transition ${active ? "bg-accent/10 font-medium text-accent" : "text-muted hover:bg-inset hover:text-fg"}`}>
                      <n.icon className="h-4 w-4" />
                      {n.label}
                      {n.demo && <span className="ml-auto text-[10px] font-semibold uppercase tracking-wide text-warn">demo</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>
        <div className="border-t border-line p-3">
          <a href="#/viewer" className="flex h-9 items-center gap-2.5 rounded-lg border border-line px-2.5 text-[13px] text-muted hover:bg-inset hover:text-fg">
            <KeyRound className="h-4 w-4" /> Open recipient viewer
          </a>
          <div className="mt-3 space-y-1 px-1 text-[11.5px] text-subtle">
            <div className="flex items-center gap-1.5"><span className={`h-1.5 w-1.5 rounded-full ${status?.ledger.valid === false ? "bg-bad" : "bg-ok"}`} />
              Ledger {status?.ledger.valid === false ? "integrity failure" : "verified"} · {status?.ledger.length ?? "–"} blocks</div>
            <div className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-ok" /> Air-gapped · loopback only</div>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-line bg-surface/80 px-6 backdrop-blur">
          <div className="flex min-w-0 items-center gap-2 text-[13px]">
            <span className="text-subtle">{visible.find((g) => g.items.includes(current))?.group}</span>
            <span className="text-line-strong">/</span>
            <span className="truncate font-medium text-fg">{current.label}</span>
          </div>
          <div className="flex items-center gap-2">
            {status?.demo_mode && <Badge tone="warn" dot>Demo mode</Badge>}
            <Badge tone="mute">{status?.pqc.kem} · {status?.pqc.signature}</Badge>
            <ThemeButton theme={theme} toggle={toggleTheme} />
            <div className="mx-1 h-6 w-px bg-line" />
            <UserMenu session={session} onLogout={logout} />
          </div>
        </header>
        <main className="min-w-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1240px] px-6 py-7">
            <C go={go} session={session} status={status} reloadStatus={reloadStatus} />
          </div>
        </main>
      </div>
    </div>
  );
}

function Shell() {
  const [theme, toggleTheme] = useTheme();
  const session = useSession();
  const status = useLoad(() => api.get("/api/status"));
  const [route] = useRoute();

  if (route === "viewer") {
    return <Viewer status={status.data} theme={theme} toggleTheme={toggleTheme} Brand={Brand} ThemeButton={ThemeButton} />;
  }
  if (!session) {
    return <Login status={status.data} reloadStatus={status.reload} theme={theme} toggleTheme={toggleTheme} Brand={Brand} ThemeButton={ThemeButton} />;
  }
  return <Console session={session} status={status.data} reloadStatus={status.reload} theme={theme} toggleTheme={toggleTheme} />;
}

export default function App() {
  return (
    <ToastProvider>
      <Shell />
    </ToastProvider>
  );
}
