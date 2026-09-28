import React, { useState } from "react";
import { ArrowLeft, CheckCircle2, Download, FileLock2, KeyRound, Lock, ShieldCheck, UserRound } from "lucide-react";
import { api, saveBlob } from "../api.js";
import { Alert, Badge, Button, ErrorBox, Field, Hash, KV, Spinner, useAction, useLoad } from "../components/ui.jsx";

const STEP_LABEL = {
  "token-login": "Token unlocked with PIN",
  "ml-kem-decapsulate": "Content key recovered (ML-KEM-768)",
  "aes-256-gcm-decrypt": "Document decrypted & hash verified",
  "hkdf-watermark-seed": "Session watermark derived (HKDF)",
  "watermark-embed": "Invisible watermark embedded",
  "ml-dsa-sign": "Decryption record signed (ML-DSA-65)",
  "ledger-commit": "Committed to the audit ledger",
  deliver: "Copy ready",
};

function StepPill({ n, label, active, done }) {
  return (
    <div className="flex items-center gap-2">
      <span className={`flex h-6 w-6 items-center justify-center rounded-full text-[11.5px] font-semibold ${done ? "bg-ok text-white" : active ? "bg-accent text-accent-fg" : "bg-inset text-subtle ring-1 ring-line"}`}>
        {done ? "✓" : n}
      </span>
      <span className={`text-[13px] ${active || done ? "font-medium text-fg" : "text-subtle"}`}>{label}</span>
    </div>
  );
}

export default function Viewer({ theme, toggleTheme, Brand, ThemeButton }) {
  const dir = useLoad(() => api.get("/api/viewer/directory"));
  const [doc, setDoc] = useState(null);
  const [who, setWho] = useState(null);
  const [pin, setPin] = useState("");
  const [result, setResult] = useState(null);
  const [downloaded, setDownloaded] = useState(false);
  const act = useAction();

  const docs = dir.data?.documents || [];
  const people = (dir.data?.recipients || []).filter((r) => docs.find((d) => d.id === doc)?.recipients.includes(r.id));
  const step = result ? 3 : who ? 2 : doc ? 1 : 0;

  const open = (e) => {
    e.preventDefault();
    act.run(async () => {
      const r = await api.post("/api/sessions/decrypt", { doc_id: doc, recipient_id: who, pin });
      setPin("");
      setResult(r);
      setDownloaded(false);
    });
  };
  const download = () => act.run(async () => {
    const blob = await api.blob(result.download_url);
    saveBlob(blob, `${docs.find((d) => d.id === doc)?.title || "document"} - ${result.session_id}.pdf`);
    setDownloaded(true);
  });
  const restart = () => { setResult(null); setWho(null); setDoc(null); act.setError(null); dir.reload(); };

  return (
    <div className="flex h-full flex-col">
      <header className="flex h-14 shrink-0 items-center justify-between border-b border-line bg-surface px-6">
        <div className="flex items-center gap-4"><Brand /><span className="hidden h-5 w-px bg-line sm:block" /><span className="hidden text-[13px] font-medium text-muted sm:block">Recipient secure viewer</span></div>
        <div className="flex items-center gap-2">
          <a href="#/dashboard" className="text-[13px] text-muted hover:text-fg">Operator console →</a>
          <ThemeButton theme={theme} toggle={toggleTheme} />
        </div>
      </header>
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-3xl px-6 py-10">
          <div className="mb-8 text-center">
            <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10 text-accent"><Lock className="h-6 w-6" /></span>
            <h1 className="mt-4 text-[22px] font-semibold tracking-tight">Open a protected document</h1>
            <p className="mx-auto mt-1 max-w-lg text-[13.5px] text-muted">
              Decryption happens on this machine with your personal token. Your copy carries an invisible watermark tied to this session, and the event is signed and logged.
            </p>
          </div>

          <div className="mb-6 flex flex-wrap items-center justify-center gap-x-6 gap-y-2">
            <StepPill n={1} label="Document" active={step === 0} done={step > 0} />
            <span className="h-px w-8 bg-line-strong" />
            <StepPill n={2} label="Identity" active={step === 1} done={step > 1} />
            <span className="h-px w-8 bg-line-strong" />
            <StepPill n={3} label="Unlock" active={step === 2} done={step > 2} />
          </div>

          <div className="card p-6">
            {dir.loading && !dir.data && <Spinner />}
            <ErrorBox error={dir.error} />

            {!result && step === 0 && (
              <div className="space-y-2">
                {docs.map((d) => (
                  <button key={d.id} onClick={() => setDoc(d.id)} className="flex w-full items-center gap-3 rounded-lg border border-line px-4 py-3 text-left transition hover:border-accent hover:bg-accent/5">
                    <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/10 text-accent"><FileLock2 className="h-[18px] w-[18px]" /></span>
                    <span className="flex-1"><span className="block text-[13.5px] font-medium">{d.title}</span><span className="block text-[12px] text-subtle">{d.pages} pages · {d.recipients.length} authorised</span></span>
                  </button>
                ))}
                {dir.data && !docs.length && <div className="py-6 text-center text-[13px] text-subtle">No documents have been shared on this installation.</div>}
              </div>
            )}

            {!result && step === 1 && (
              <div>
                <button onClick={() => setDoc(null)} className="mb-4 inline-flex items-center gap-1 text-[12.5px] text-subtle hover:text-fg"><ArrowLeft className="h-3.5 w-3.5" /> Choose another document</button>
                <div className="space-y-2">
                  {people.map((r) => (
                    <button key={r.id} onClick={() => setWho(r.id)} className="flex w-full items-center gap-3 rounded-lg border border-line px-4 py-3 text-left transition hover:border-accent hover:bg-accent/5">
                      <span className="flex h-9 w-9 items-center justify-center rounded-full bg-inset text-subtle ring-1 ring-line"><UserRound className="h-[18px] w-[18px]" /></span>
                      <span className="flex-1"><span className="block text-[13.5px] font-medium">{r.name}</span><span className="block text-[12px] text-subtle">{r.department || "—"}</span></span>
                      <span className="font-mono text-[11.5px] text-subtle">{r.employee_id}</span>
                    </button>
                  ))}
                  {!people.length && <div className="py-6 text-center text-[13px] text-subtle">No active recipients hold a key for this document.</div>}
                </div>
              </div>
            )}

            {!result && step === 2 && (
              <form onSubmit={open}>
                <button type="button" onClick={() => { setWho(null); act.setError(null); }} className="mb-4 inline-flex items-center gap-1 text-[12.5px] text-subtle hover:text-fg"><ArrowLeft className="h-3.5 w-3.5" /> Not you?</button>
                <div className="mb-5 flex items-center gap-3 rounded-lg bg-inset px-4 py-3">
                  <KeyRound className="h-5 w-5 text-accent" />
                  <div className="text-[13px]"><span className="font-medium">{people.find((p) => p.id === who)?.name}</span> <span className="text-subtle">· opening “{docs.find((d) => d.id === doc)?.title}”</span></div>
                </div>
                <Field label="Token PIN">
                  <input autoFocus className="input h-11 text-center font-mono text-lg tracking-[0.5em]" type="password" inputMode="numeric" autoComplete="off" value={pin} onChange={(e) => setPin(e.target.value)} required />
                </Field>
                <ErrorBox error={act.error} className="mt-3" />
                <Button variant="primary" size="lg" className="mt-4 w-full" busy={act.busy} icon={Lock}>{act.busy ? "Decrypting & watermarking…" : "Unlock & decrypt"}</Button>
                <p className="mt-3 text-center text-[12px] text-subtle">Repeated wrong PINs lock the token temporarily.</p>
              </form>
            )}

            {result && (
              <div className="animate-rise">
                <div className="flex items-center gap-3">
                  <CheckCircle2 className="h-7 w-7 text-ok" />
                  <div>
                    <div className="text-[15px] font-semibold">Your watermarked copy is ready</div>
                    <div className="text-[12.5px] text-subtle">This download link is single-use and expires in {Math.round(result.download_expires_in / 60)} minutes.</div>
                  </div>
                </div>
                <ol className="mt-5 space-y-2 border-l border-line pl-5">
                  {result.trace.map((t) => (
                    <li key={t.step} className="relative">
                      <span className="absolute -left-[25px] top-1.5 h-2 w-2 rounded-full bg-ok ring-4 ring-surface" />
                      <div className="flex items-baseline justify-between gap-3 text-[13px]">
                        <span>{STEP_LABEL[t.step] || t.step}</span>
                        <span className="font-mono text-[11.5px] text-subtle">{t.ms} ms</span>
                      </div>
                    </li>
                  ))}
                </ol>
                <div className="mt-5 rounded-lg border border-line bg-inset p-4">
                  <KV cols={2} rows={[["Session", <span className="font-mono">{result.session_id}</span>], ["Watermark ID", <Badge tone="accent"><span className="font-mono">{result.watermark_id}</span></Badge>],
                    ["Ledger block", <span className="font-mono">#{result.block_index}</span>], ["Copy SHA3-256", <Hash value={result.record.copy_hash} n={16} />]]} />
                </div>
                <Alert tone="info" className="mt-4">This copy is uniquely linked to you and to this session. If it leaks, even as a screenshot or pasted text, it can be traced back here.</Alert>
                <ErrorBox error={act.error} className="mt-3" />
                <div className="mt-5 flex gap-2">
                  <Button variant="primary" size="lg" className="flex-1" icon={downloaded ? ShieldCheck : Download} busy={act.busy} disabled={downloaded} onClick={download}>
                    {downloaded ? "Downloaded" : "Download my copy"}
                  </Button>
                  <Button size="lg" onClick={restart}>Done</Button>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
