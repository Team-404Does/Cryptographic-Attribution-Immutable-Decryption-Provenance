import React, { useState } from "react";
import {
  Activity, ArrowRight, Blocks, FileLock2, Fingerprint, KeyRound, Network, RotateCcw, ScrollText, ShieldAlert,
  ShieldCheck, Users,
} from "lucide-react";
import { api, ago, auth } from "../api.js";
import { Badge, Button, Card, Confirm, Empty, Hash, PageHeader, Spinner, Stat, useAction, useLoad } from "../components/ui.jsx";
import { describe, eventTime, meta } from "../components/events.jsx";
import { useNames } from "../components/useNames.js";

const NODE_LABEL = { legal: "Legal", "it-security": "IT Security", compliance: "Compliance" };

const PIPELINE = [
  ["Seal", "AES-256-GCM content key, ML-KEM-768 wrap per recipient"],
  ["Authenticate", "PIN unlocks the recipient token locally"],
  ["Derive", "HKDF(recipient ‖ doc ‖ nonce ‖ time) → watermark ID"],
  ["Embed", "Keyed spread-spectrum raster + homoglyph text, RS(16,8)"],
  ["Sign", "SHA3-256 record signed with recipient ML-DSA-65"],
  ["Commit", "Merkle block endorsed 2-of-3 by ledger nodes"],
  ["Attribute", "Extract → ECC → ledger → verify → signed evidence"],
];

export default function Dashboard({ go, status, reloadStatus, session }) {
  const blocks = useLoad(() => api.get("/api/ledger/blocks?limit=12"));
  const names = useNames();
  const [confirmReset, setConfirmReset] = useState(false);
  const act = useAction();
  const s = status;

  const reset = () => act.run(async () => {
    await api.post("/api/demo/reset");
    auth.set(null);
  });

  const events = (blocks.data || []).flatMap((b) => b.events.map((e) => ({ ...e, _block: b.index }))).slice(0, 10);
  const role = session.operator.role;

  return (
    <>
      <PageHeader
        eyebrow="Overview"
        title={`Welcome back, ${session.operator.name.split(" ")[0]}`}
        subtitle="Each decryption produces a copy that looks identical but can be traced forensically. It is signed with post-quantum keys and committed to an offline ledger that shows any tampering."
        actions={<>
          <Button icon={RotateCcw} onClick={() => { reloadStatus(); blocks.reload(); }}>Refresh</Button>
          {role === "examiner" && <Button variant="primary" icon={Fingerprint} onClick={() => go("forensics")}>Analyse a leak</Button>}
          {role === "security-officer" && <Button variant="primary" icon={FileLock2} onClick={() => go("documents")}>Seal a document</Button>}
        </>}
      />
      {!s ? <Spinner /> : (
        <div className="space-y-6">
          {!s.ledger.valid && (
            <div className="flex items-center gap-4 rounded-xl border border-bad/30 bg-bad/5 p-4">
              <ShieldAlert className="h-6 w-6 shrink-0 text-bad" />
              <div className="flex-1">
                <div className="font-semibold text-fg">Ledger integrity failure detected</div>
                <div className="text-[13px] text-muted">
                  {s.ledger.first_invalid_block != null ? `Block #${s.ledger.first_invalid_block} no longer matches its committed hash.` : "Ledger nodes disagree about the chain head."} Treat attribution results as compromised until investigated.
                </div>
              </div>
              <Button variant="danger" onClick={() => go("ledger")}>Investigate</Button>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
            <Stat label="Recipients" value={s.counts.recipients} icon={Users} hint="CA-certified identities" />
            <Stat label="Sealed documents" value={s.counts.documents} icon={FileLock2} hint="AES-256-GCM at rest" />
            <Stat label="Decryption sessions" value={s.counts.sessions} icon={KeyRound} hint="each uniquely watermarked" />
            <Stat label="Ledger blocks" value={s.counts.blocks} icon={Blocks} hint={`${s.ledger.quorum} endorsed`} />
            <Stat label="Evidence reports" value={s.counts.reports} icon={ScrollText} hint="dual ML-DSA signed" />
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <Card className="lg:col-span-2" title="Recent ledger activity" subtitle="Every administrative action and decryption is signed and chained"
              actions={<Button size="sm" variant="ghost" onClick={() => go("ledger")}>View ledger <ArrowRight className="h-3.5 w-3.5" /></Button>} pad={false}>
              {blocks.loading && !blocks.data ? <div className="p-5"><Spinner /></div> : events.length === 0 ? <Empty icon={Activity} title="No activity yet" /> : (
                <ul className="divide-y divide-line">
                  {events.map((e, i) => {
                    const m = meta(e.type);
                    return (
                      <li key={i} className="flex items-center gap-3 px-5 py-3">
                        <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-${m.tone === "mute" ? "info" : m.tone}/10 text-${m.tone === "mute" ? "info" : m.tone}`}><m.icon className="h-4 w-4" /></span>
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-[13px] text-fg">{describe(e, names)}</div>
                          <div className="text-[12px] text-subtle">{m.label} · block #{e._block}</div>
                        </div>
                        <span className="shrink-0 text-[12px] text-subtle">{ago(eventTime(e))}</span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Card>

            <div className="space-y-6">
              <Card title="Ledger health" actions={s.ledger.valid ? <Badge tone="ok" dot>Verified</Badge> : <Badge tone="bad" dot>Failed</Badge>}>
                <div className="space-y-2.5">
                  {s.ledger.nodes.map((n) => (
                    <div key={n.node} className="flex items-center gap-3">
                      <Network className="h-4 w-4 text-subtle" />
                      <span className="flex-1 text-[13px]">{NODE_LABEL[n.node] || n.node}</span>
                      <span className="font-mono text-[11.5px] text-subtle">#{n.index}</span>
                      <Badge tone={n.status === "in-sync" ? "ok" : "bad"}>{n.status}</Badge>
                    </div>
                  ))}
                </div>
                <div className="mt-4 border-t border-line pt-3">
                  <div className="text-[12px] text-subtle">Chain head</div>
                  <Hash value={s.ledger.head} n={28} />
                </div>
              </Card>
              <Card title="Cryptographic suite">
                <dl className="space-y-2 text-[13px]">
                  {[["Key encapsulation", s.pqc.kem], ["Signatures", s.pqc.signature], ["Content encryption", "AES-256-GCM"],
                    ["KDF · hash", "HKDF-SHA3 · SHA3-256"], ["Watermark ECC", "Reed-Solomon (16,8)"]].map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-3"><dt className="text-muted">{k}</dt><dd className="font-medium">{v}</dd></div>
                  ))}
                </dl>
                <div className="mt-4 rounded-lg bg-inset p-3 text-[12px] leading-relaxed text-subtle">
                  <ShieldCheck className="mb-1 h-4 w-4 text-ok" />
                  {s.pqc.backend}<br />Root: {s.ca}
                </div>
              </Card>
            </div>
          </div>

          <Card title="Attribution pipeline" subtitle="What happens between sealing a document and naming the leaker">
            <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-7">
              {PIPELINE.map(([t, d], i) => (
                <li key={t} className="relative rounded-lg border border-line bg-inset p-3">
                  <div className="font-mono text-[11px] font-medium text-accent">{String(i + 1).padStart(2, "0")}</div>
                  <div className="mt-1 text-[13px] font-semibold">{t}</div>
                  <div className="mt-1 text-[12px] leading-relaxed text-subtle">{d}</div>
                </li>
              ))}
            </ol>
          </Card>

          {s.demo_mode && role === "security-officer" && (
            <Card title="Demo tools" subtitle="Only available when the server runs with SIH_DEMO=1">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <p className="max-w-2xl text-[13px] text-muted">
                  Wipes every key, document, ledger block and report, then returns to the first-run screen so you can load a fresh demo environment.
                </p>
                <Button variant="danger" icon={RotateCcw} onClick={() => setConfirmReset(true)}>Reset environment</Button>
              </div>
            </Card>
          )}
        </div>
      )}
      <Confirm open={confirmReset} onClose={() => setConfirmReset(false)} onConfirm={reset} busy={act.busy} danger
        title="Reset the demo environment?" confirmLabel="Wipe everything">
        This permanently deletes all tokens, certificates, documents, the ledger and reports on this installation.
      </Confirm>
    </>
  );
}
