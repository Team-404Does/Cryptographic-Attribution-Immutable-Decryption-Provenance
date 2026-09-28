import React, { useState } from "react";
import { CheckCircle2, Link2, Network, RefreshCw, RotateCcw, ShieldAlert, Skull } from "lucide-react";
import { api, when } from "../api.js";
import { Badge, Button, Card, Confirm, Drawer, ErrorBox, Hash, KV, PageHeader, Spinner, useAction, useLoad } from "../components/ui.jsx";
import { describe, EVENT_META, meta } from "../components/events.jsx";
import { useNames } from "../components/useNames.js";

const NODE_LABEL = { legal: "Legal", "it-security": "IT Security", compliance: "Compliance" };
const CHECKS = [["merkle_root_ok", "Merkle root"], ["header_hash_ok", "Header hash"], ["prev_link_ok", "Previous link"], ["quorum_ok", "2-of-3 quorum"]];

function failure(s) {
  if (!s || s.ok) return null;
  if (!s.merkle_root_ok) return "events altered (Merkle mismatch)";
  if (!s.header_hash_ok) return "header altered";
  if (!s.prev_link_ok) return "chain link broken";
  return "endorsement quorum failed";
}

function BlockDrawer({ b, s, names, canTamper, onClose, onTamper }) {
  const [confirm, setConfirm] = useState(false);
  return (
    <Drawer open onClose={onClose} title={`Block #${b.index}`} subtitle={when(b.header.timestamp)}
      actions={s && (s.ok ? <Badge tone="ok" dot>Valid</Badge> : <Badge tone="bad" dot>{failure(s)}</Badge>)}>
      <div className="space-y-6">
        {s && <div className="grid grid-cols-2 gap-2">
          {CHECKS.map(([k, l]) => (
            <div key={k} className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-[12.5px] ${s[k] ? "border-ok/25 bg-ok/5" : "border-bad/30 bg-bad/5"}`}>
              {s[k] ? <CheckCircle2 className="h-4 w-4 text-ok" /> : <ShieldAlert className="h-4 w-4 text-bad" />}{l}
              {k === "quorum_ok" && <span className="ml-auto font-mono text-subtle">{s.endorsements_valid}/3</span>}
            </div>
          ))}
        </div>}
        <section>
          <div className="eyebrow mb-3">Header</div>
          <KV rows={[["Block hash", <Hash value={b.block_hash} full />], ["Previous hash", <Hash value={b.header.prev_hash} full />],
            ["Merkle root", <Hash value={b.header.merkle_root} full />], ["Events", b.header.event_count], ["Version", b.header.version]]} />
        </section>
        <section>
          <div className="eyebrow mb-3">Node endorsements (ML-DSA-65)</div>
          <div className="space-y-1.5">
            {b.endorsements.map((e) => (
              <div key={e.node} className="flex items-center gap-3 rounded-lg border border-line px-3 py-2">
                <Network className="h-4 w-4 text-subtle" /><span className="w-24 text-[13px]">{NODE_LABEL[e.node]}</span>
                <Hash value={e.signature} n={36} />
              </div>
            ))}
          </div>
        </section>
        <section>
          <div className="eyebrow mb-3">Events</div>
          <div className="space-y-3">
            {b.events.map((e, i) => {
              const m = meta(e.type);
              return (
                <div key={i} className="rounded-lg border border-line">
                  <div className="flex items-center gap-2 border-b border-line px-3 py-2">
                    <m.icon className={`h-4 w-4 text-${m.tone === "mute" ? "info" : m.tone}`} />
                    <span className="text-[13px] font-medium">{m.label}</span>
                    <span className="ml-auto text-[12px] text-subtle">{describe(e, names)}</span>
                  </div>
                  <pre className="max-h-72 overflow-auto bg-inset p-3 font-mono text-[11.5px] leading-relaxed text-muted">
                    {JSON.stringify(e.signature ? { ...e, signature: `${e.signature.slice(0, 48)}…` } : e, null, 2)}
                  </pre>
                </div>
              );
            })}
          </div>
        </section>
        {canTamper && b.index > 0 && (
          <div className="rounded-xl border border-bad/30 bg-bad/5 p-4">
            <div className="text-[13px] font-medium">Simulate an insider edit</div>
            <p className="mt-1 text-[12.5px] text-muted">Rewrites this block's stored event directly in the database, bypassing the API, as a rogue administrator would. The audit should flag it at once.</p>
            <Button className="mt-3" variant="danger" icon={Skull} onClick={() => setConfirm(true)}>Tamper with this block</Button>
          </div>
        )}
      </div>
      <Confirm open={confirm} onClose={() => setConfirm(false)} danger title={`Tamper with block #${b.index}?`} confirmLabel="Rewrite record"
        onConfirm={() => { setConfirm(false); onTamper(b.index); }}>
        Demo only. You can undo it afterwards with “Restore original”.
      </Confirm>
    </Drawer>
  );
}

export default function Ledger({ session, status, reloadStatus }) {
  const blocks = useLoad(() => api.get("/api/ledger/blocks?limit=500"));
  const audit = useLoad(() => api.get("/api/ledger/verify"));
  const names = useNames();
  const [open, setOpen] = useState(null);
  const [filter, setFilter] = useState("all");
  const act = useAction();
  const canTamper = status?.demo_mode && session.operator.role === "security-officer";

  const st = Object.fromEntries((audit.data?.blocks || []).map((b) => [b.index, b]));
  const refresh = () => Promise.all([blocks.reload(), audit.reload(), reloadStatus()]);
  const tamper = (idx) => act.run(async () => { await api.post("/api/demo/tamper", { block_index: idx }); setOpen(null); await refresh(); },
    { success: `Block #${idx} rewritten. Run the audit to see it detected.` });
  const repair = () => act.run(async () => { await api.post("/api/demo/repair"); await refresh(); }, { success: "Original records restored" });

  const a = audit.data;
  const list = (blocks.data || []).filter((b) => filter === "all" || b.events.some((e) => e.type === filter));
  const types = [...new Set((blocks.data || []).flatMap((b) => b.events.map((e) => e.type)))];
  const current = (blocks.data || []).find((b) => b.index === open);

  return (
    <>
      <PageHeader eyebrow="Assurance" title="Audit ledger"
        subtitle="An append-only hash chain of Merkle-rooted blocks. Each block needs ML-DSA endorsements from 2 of 3 internal nodes, and each node tracks the head separately. Editing any past record breaks the chain."
        actions={<>
          {canTamper && <Button icon={RotateCcw} busy={act.busy} onClick={repair}>Restore original</Button>}
          <Button variant="primary" icon={RefreshCw} busy={audit.loading} onClick={refresh}>Run full audit</Button>
        </>} />
      <ErrorBox error={blocks.error || audit.error || act.error} className="mb-4" />

      {a && (
        <div className="mb-6 grid gap-4 lg:grid-cols-[1.4fr_1fr]">
          <div className={`card flex items-center gap-4 p-5 ${a.valid ? "" : "border-bad/40"}`}>
            <span className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl ${a.valid ? "bg-ok/10 text-ok" : "bg-bad/10 text-bad"}`}>
              {a.valid ? <CheckCircle2 className="h-6 w-6" /> : <ShieldAlert className="h-6 w-6" />}
            </span>
            <div className="min-w-0">
              <div className="text-[15px] font-semibold">{a.valid ? "Chain integrity verified" : `Tampering detected at block #${a.first_invalid_block ?? "?"}`}</div>
              <div className="mt-0.5 text-[12.5px] text-muted">{a.length} blocks · audited {when(a.checked_at)}</div>
              <div className="mt-1"><Hash value={a.head_hash} n={40} /></div>
            </div>
          </div>
          <div className="card p-5">
            <div className="eyebrow mb-3">Node consensus</div>
            <div className="grid grid-cols-3 gap-2">
              {a.node_health.nodes.map((n) => (
                <div key={n.node} className={`rounded-lg border p-2.5 ${n.status === "in-sync" ? "border-line" : "border-bad/40 bg-bad/5"}`}>
                  <div className="text-[12.5px] font-medium">{NODE_LABEL[n.node]}</div>
                  <div className={`mt-0.5 text-[11.5px] ${n.status === "in-sync" ? "text-ok" : "text-bad"}`}>{n.status}</div>
                  <div className="font-mono text-[11px] text-subtle">head #{n.index}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <Card pad={false} title={`Blocks (${list.length})`} actions={
        <select className="input h-8 w-52 text-[12.5px]" value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="all">All event types</option>
          {types.map((t) => <option key={t} value={t}>{EVENT_META[t]?.label || t}</option>)}
        </select>}>
        {blocks.loading && !blocks.data ? <div className="p-5"><Spinner /></div> : (
          <ol className="relative px-5 py-4">
            {list.map((b, i) => {
              const s = st[b.index];
              const bad = s && !s.ok;
              const e = b.events[0];
              const m = meta(e.type);
              return (
                <li key={b.index} className="relative pl-10">
                  {i < list.length - 1 && <span className={`absolute left-[15px] top-9 h-[calc(100%-20px)] w-px ${bad ? "bg-bad/50" : "bg-line-strong"}`} />}
                  <span className={`absolute left-0 top-2.5 flex h-8 w-8 items-center justify-center rounded-lg ring-1 ${bad ? "bg-bad/10 text-bad ring-bad/30" : "bg-surface text-subtle ring-line-strong"}`}>
                    <Link2 className="h-4 w-4" />
                  </span>
                  <button onClick={() => setOpen(b.index)}
                    className={`mb-2 flex w-full items-center gap-4 rounded-lg border px-4 py-3 text-left transition hover:bg-inset ${bad ? "border-bad/40 bg-bad/5" : "border-line"}`}>
                    <span className="w-12 shrink-0 font-mono text-[13px] font-medium text-fg">#{b.index}</span>
                    <m.icon className={`h-4 w-4 shrink-0 text-${m.tone === "mute" ? "info" : m.tone}`} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[13px] text-fg">{describe(e, names)}{b.events.length > 1 && <span className="text-subtle"> · +{b.events.length - 1} more event(s)</span>}</div>
                      <div className="mt-0.5 flex gap-3 font-mono text-[11.5px] text-subtle">
                        <span>hash {b.block_hash.slice(0, 12)}…</span><span>prev {b.header.prev_hash.slice(0, 12)}…</span>
                      </div>
                    </div>
                    {s && (s.ok ? <Badge tone="ok">{s.endorsements_valid}/3 endorsed</Badge> : <Badge tone="bad">{failure(s)}</Badge>)}
                    <span className="hidden w-36 shrink-0 text-right text-[12px] text-subtle md:block">{when(b.header.timestamp)}</span>
                  </button>
                </li>
              );
            })}
          </ol>
        )}
      </Card>
      {current && <BlockDrawer b={current} s={st[current.index]} names={names} canTamper={canTamper} onClose={() => setOpen(null)} onTamper={tamper} />}
    </>
  );
}
