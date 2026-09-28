import React, { useEffect, useState } from "react";
import { ArrowRight, Fingerprint, KeyRound, Link2, Lock, ShieldCheck, Sparkles, Waypoints } from "lucide-react";
import { api, auth, ROLE_LABEL } from "../api.js";
import { Alert, Button, ErrorBox, Field, Spinner, useAction, useLoad } from "../components/ui.jsx";

const DEMO_PINS = { "Priya Nair": "9000", "Arjun Rao": "9100", "Meera Das": "9200" };

const FEATURES = [
  [Fingerprint, "Session-level attribution", "Every decryption carries a unique invisible watermark, so a leak points to the exact session."],
  [KeyRound, "Post-quantum identity", "ML-KEM-768 key wrapping and ML-DSA-65 signatures on every record."],
  [Link2, "Tamper-evident provenance", "Merkle-rooted hash chain, 2-of-3 endorsed by internal ledger nodes."],
];

function Splash({ Brand }) {
  return (
    <div className="relative hidden flex-col justify-between overflow-hidden border-r border-line bg-surface p-10 lg:flex">
      <div className="pointer-events-none absolute -right-24 -top-24 h-80 w-80 rounded-full bg-accent/10 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-32 -left-20 h-96 w-96 rounded-full bg-info/10 blur-3xl" />
      <Brand />
      <div className="relative">
        <div className="eyebrow mb-3">Cryptographic attribution & immutable decryption provenance</div>
        <h1 className="max-w-md text-[28px] font-semibold leading-tight tracking-tight text-fg">
          Know exactly who opened it, and which copy leaked.
        </h1>
        <div className="mt-8 space-y-5">
          {FEATURES.map(([I, t, d]) => (
            <div key={t} className="flex gap-3.5">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent/10 text-accent ring-1 ring-accent/15"><I className="h-[18px] w-[18px]" /></span>
              <div>
                <div className="text-[13.5px] font-medium text-fg">{t}</div>
                <div className="mt-0.5 max-w-sm text-[13px] leading-relaxed text-muted">{d}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="relative flex items-center gap-2 text-[12px] text-subtle">
        <Lock className="h-3.5 w-3.5" /> Offline installation · no cloud KMS · no public network
      </div>
    </div>
  );
}

function Bootstrap({ status, reloadStatus }) {
  const [f, setF] = useState({ name: "", pin: "", confirm: "", code: "" });
  const act = useAction();
  const [seeded, setSeeded] = useState(null);

  const init = (e) => {
    e.preventDefault();
    if (f.pin !== f.confirm) return act.setError("PINs do not match");
    act.run(async () => {
      const s = await api.post("/api/auth/bootstrap", { name: f.name, pin: f.pin, setup_code: f.code });
      auth.set(s);
      reloadStatus();
    });
  };
  const seed = () => act.run(async () => setSeeded(await api.post("/api/demo/seed")));   // status refresh on Continue

  if (seeded) {
    return (
      <div className="space-y-4">
        <Alert tone="ok" title="Demo environment ready">Operators, recipients and a sealed memorandum were provisioned and recorded on the ledger.</Alert>
        <div className="rounded-lg border border-line bg-inset p-4 text-[13px]">
          <div className="eyebrow mb-2">Credentials</div>
          {Object.entries(seeded.operators).map(([n, o]) => (
            <div key={n} className="flex justify-between py-0.5"><span>{n} <span className="text-subtle">· {ROLE_LABEL[o.role]}</span></span><span className="font-mono">{o.pin}</span></div>
          ))}
          <div className="my-2 border-t border-line" />
          {Object.entries(seeded.recipient_pins).map(([n, p]) => (
            <div key={n} className="flex justify-between py-0.5"><span>{n} <span className="text-subtle">· recipient</span></span><span className="font-mono">{p}</span></div>
          ))}
        </div>
        <Button variant="primary" className="w-full" onClick={() => { setSeeded(null); reloadStatus(); }} icon={ArrowRight}>Continue to sign in</Button>
      </div>
    );
  }

  return (
    <>
      <div className="mb-6">
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl bg-accent/10 text-accent"><Waypoints className="h-5 w-5" /></div>
        <h2 className="text-xl font-semibold tracking-tight">Initialise installation</h2>
        <p className="mt-1 text-[13.5px] text-muted">Create the first security officer. Their token is generated locally and certified by the offline root CA. The ceremony is recorded as block 1 of the ledger.</p>
      </div>
      <form onSubmit={init} className="space-y-4">
        <Field label="One-time setup code" hint="Printed in the server console at start-up (also in data/setup-code.txt).">
          <input className="input font-mono uppercase tracking-widest" placeholder="XXXX-XXXX-XXXX" value={f.code} onChange={(e) => setF({ ...f, code: e.target.value })} required />
        </Field>
        <Field label="Officer full name"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required /></Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Token PIN" hint="4–12 digits"><input className="input" type="password" inputMode="numeric" value={f.pin} onChange={(e) => setF({ ...f, pin: e.target.value })} required /></Field>
          <Field label="Confirm PIN"><input className="input" type="password" inputMode="numeric" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} required /></Field>
        </div>
        <ErrorBox error={act.error} />
        <Button variant="primary" size="lg" className="w-full" busy={act.busy} icon={ShieldCheck}>Create security officer</Button>
      </form>
      {status?.demo_mode && (
        <div className="mt-6 rounded-xl border border-warn/30 bg-warn/5 p-4">
          <div className="flex items-center gap-2 text-[13px] font-medium text-fg"><Sparkles className="h-4 w-4 text-warn" /> Demo mode</div>
          <p className="mt-1 text-[12.5px] text-muted">Provision a complete sample environment: 3 operators, 3 recipients and a sealed memorandum.</p>
          <Button className="mt-3 w-full" busy={act.busy} onClick={seed}>Load demo environment</Button>
        </div>
      )}
    </>
  );
}

function SignIn({ status }) {
  const ops = useLoad(() => api.get("/api/auth/operators"));
  const [sel, setSel] = useState(null);
  const [pin, setPin] = useState("");
  const act = useAction();
  useEffect(() => { if (ops.data?.length && !sel) setSel(ops.data[0].id); }, [ops.data, sel]);
  const chosen = ops.data?.find((o) => o.id === sel);

  const submit = (e) => {
    e.preventDefault();
    act.run(async () => auth.set(await api.post("/api/auth/login", { operator_id: sel, pin })));
  };

  return (
    <>
      <div className="mb-6">
        <h2 className="text-xl font-semibold tracking-tight">Operator sign-in</h2>
        <p className="mt-1 text-[13.5px] text-muted">Select your token and enter its PIN. Five wrong attempts lock the token.</p>
      </div>
      {ops.loading && <Spinner />}
      <form onSubmit={submit} className="space-y-4">
        <div className="space-y-1.5">
          {(ops.data || []).map((o) => (
            <button type="button" key={o.id} onClick={() => { setSel(o.id); setPin(""); }}
              className={`flex w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-left transition ${sel === o.id ? "border-accent bg-accent/5 ring-[3px] ring-accent/15" : "border-line hover:border-line-strong hover:bg-inset"}`}>
              <span className="flex h-8 w-8 items-center justify-center rounded-full bg-inset text-[11.5px] font-semibold text-muted ring-1 ring-line">
                {o.name.split(" ").map((p) => p[0]).slice(0, 2).join("")}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[13.5px] font-medium text-fg">{o.name}</span>
                <span className="block text-[12px] text-subtle">{ROLE_LABEL[o.role]}</span>
              </span>
              {status?.demo_mode && DEMO_PINS[o.name] && <span className="font-mono text-[11px] text-subtle">PIN {DEMO_PINS[o.name]}</span>}
            </button>
          ))}
        </div>
        <Field label={chosen ? `PIN for ${chosen.name}` : "PIN"}>
          <input className="input h-10 font-mono tracking-[0.3em]" type="password" inputMode="numeric" autoComplete="off"
            value={pin} onChange={(e) => setPin(e.target.value)} required />
        </Field>
        <ErrorBox error={act.error} />
        <Button variant="primary" size="lg" className="w-full" busy={act.busy} disabled={!sel} icon={Lock}>Unlock token & sign in</Button>
      </form>
    </>
  );
}

export default function Login({ status, reloadStatus, theme, toggleTheme, Brand, ThemeButton }) {
  return (
    <div className="grid h-full lg:grid-cols-[1.05fr_1fr]">
      <Splash Brand={Brand} />
      <div className="flex flex-col overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4">
          <div className="lg:invisible"><Brand /></div>
          <ThemeButton theme={theme} toggle={toggleTheme} />
        </div>
        <div className="flex flex-1 items-center justify-center px-6 pb-10">
          <div className="w-full max-w-[400px] animate-rise">
            {!status ? <Spinner /> : status.bootstrap_required ? <Bootstrap status={status} reloadStatus={reloadStatus} /> : <SignIn status={status} />}
            <div className="mt-8 border-t border-line pt-5 text-center text-[13px] text-muted">
              Are you a document recipient?{" "}
              <a href="#/viewer" className="link">Open the secure viewer →</a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
