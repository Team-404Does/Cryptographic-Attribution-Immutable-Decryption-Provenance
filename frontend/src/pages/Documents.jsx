import React, { useState } from "react";
import { FileLock2, FileUp, Plus, ShieldCheck, Unlink, UploadCloud } from "lucide-react";
import { api, when } from "../api.js";
import {
  Badge, Button, Card, Confirm, Drawer, Empty, ErrorBox, Field, Hash, KV, Modal, PageHeader, Spinner, Table,
  useAction, useLoad,
} from "../components/ui.jsx";

function SealModal({ open, onClose, recipients, onDone }) {
  const [file, setFile] = useState(null);
  const [title, setTitle] = useState("");
  const [chosen, setChosen] = useState([]);
  const [drag, setDrag] = useState(false);
  const act = useAction();
  const active = recipients.filter((r) => r.status === "active");
  const toggle = (id) => setChosen((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id]));
  const submit = () => act.run(async () => {
    const d = await api.upload("/api/documents", { file, title, recipients: chosen.join(",") });
    setFile(null); setTitle(""); setChosen([]);
    onDone(d);
    return d;
  }, { success: (d) => `“${d.title}” sealed for ${d.recipients.length} recipient(s)` });

  return (
    <Modal open={open} onClose={onClose} title="Seal a document" width="max-w-2xl"
      subtitle="The PDF is encrypted with a fresh AES-256-GCM key, which is then wrapped with ML-KEM-768 for each recipient you select."
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" icon={FileLock2} busy={act.busy} disabled={!file} onClick={submit}>Encrypt & wrap keys</Button></>}>
      <div className="space-y-4">
        <label onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); setFile(e.dataTransfer.files[0]); }}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-8 text-center transition ${drag ? "border-accent bg-accent/5" : "border-line-strong hover:bg-inset"}`}>
          <input type="file" accept="application/pdf" className="hidden" onChange={(e) => setFile(e.target.files[0])} />
          <UploadCloud className="h-7 w-7 text-subtle" />
          {file ? <div className="mt-2 text-[13.5px] font-medium">{file.name} <span className="text-subtle">· {(file.size / 1024).toFixed(1)} KB</span></div>
            : <><div className="mt-2 text-[13.5px] font-medium">Drop a PDF or click to browse</div><div className="text-[12px] text-subtle">Up to 100 pages · 50 MB</div></>}
        </label>
        <Field label="Title"><input className="input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder={file?.name || "Defaults to the file name"} /></Field>
        <Field label={`Authorised recipients (${chosen.length} selected)`}>
          <div className="max-h-56 divide-y divide-line overflow-y-auto rounded-lg border border-line">
            {active.map((r) => (
              <label key={r.id} className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-inset">
                <input type="checkbox" className="h-4 w-4 accent-[rgb(var(--accent))]" checked={chosen.includes(r.id)} onChange={() => toggle(r.id)} />
                <span className="flex-1 text-[13px]">{r.name} <span className="text-subtle">· {r.department || "—"}</span></span>
                <span className="font-mono text-[11.5px] text-subtle">{r.employee_id}</span>
              </label>
            ))}
            {!active.length && <div className="p-3 text-[13px] text-subtle">No active recipients. Enrol recipients first.</div>}
          </div>
        </Field>
        <ErrorBox error={act.error} />
      </div>
    </Modal>
  );
}

function DocDrawer({ doc, recipients, canManage, onClose, onChanged }) {
  const [revoke, setRevoke] = useState(null);
  const act = useAction();
  const byId = Object.fromEntries(recipients.map((r) => [r.id, r]));
  const others = recipients.filter((r) => r.status === "active" && !doc.recipients.includes(r.id));
  const grant = (rid) => act.run(async () => { await api.post(`/api/documents/${doc.id}/grant`, { recipient_id: rid }); onChanged(); },
    { success: `Access granted to ${byId[rid]?.name}` });
  const doRevoke = () => act.run(async () => { await api.post(`/api/documents/${doc.id}/revoke`, { recipient_id: revoke }); setRevoke(null); onChanged(); },
    { success: "Access revoked" });

  return (
    <Drawer open onClose={onClose} title={doc.title} subtitle={<span className="font-mono">{doc.id}</span>}>
      <div className="space-y-6">
        <KV cols={2} rows={[["Pages", doc.pages], ["Size", `${(doc.size / 1024).toFixed(1)} KB`], ["Sealed", when(doc.created_at)],
          ["Sealed by", doc.created_by_name || doc.created_by], ["Decryption sessions", doc.sessions], ["Original file", doc.filename]]} />
        <div><div className="text-[12px] text-subtle">Plaintext SHA3-256</div><Hash value={doc.sha3} full /></div>
        <section>
          <div className="eyebrow mb-2">Access ({doc.recipients.length})</div>
          <div className="divide-y divide-line rounded-lg border border-line">
            {doc.recipients.map((rid) => (
              <div key={rid} className="flex items-center gap-3 px-3 py-2.5">
                <ShieldCheck className="h-4 w-4 text-ok" />
                <div className="min-w-0 flex-1"><div className="text-[13px] font-medium">{byId[rid]?.name || rid}</div><div className="font-mono text-[11.5px] text-subtle">{byId[rid]?.employee_id} · ML-KEM-768 wrap</div></div>
                {byId[rid]?.status === "revoked" && <Badge tone="bad">identity revoked</Badge>}
                {canManage && <Button size="sm" variant="ghost" icon={Unlink} onClick={() => setRevoke(rid)}>Revoke</Button>}
              </div>
            ))}
            {!doc.recipients.length && <div className="p-3 text-[13px] text-subtle">Nobody can decrypt this document yet.</div>}
          </div>
        </section>
        {canManage && others.length > 0 && (
          <section>
            <div className="eyebrow mb-2">Grant access</div>
            <div className="flex flex-wrap gap-2">
              {others.map((r) => <Button key={r.id} size="sm" icon={Plus} busy={act.busy} onClick={() => grant(r.id)}>{r.name}</Button>)}
            </div>
            <p className="mt-2 text-[12px] text-subtle">The escrowed content key is unwrapped by the custodian token and re-wrapped for the new recipient. The grant is signed by you.</p>
          </section>
        )}
        <ErrorBox error={act.error} />
      </div>
      <Confirm open={!!revoke} onClose={() => setRevoke(null)} onConfirm={doRevoke} busy={act.busy} danger title="Revoke access?" confirmLabel="Revoke access">
        {byId[revoke]?.name}'s key wrap will be deleted, so future decryption attempts will fail. Copies they already decrypted stay attributable.
      </Confirm>
    </Drawer>
  );
}

export default function Documents({ session }) {
  const docs = useLoad(() => api.get("/api/documents"));
  const rcps = useLoad(() => api.get("/api/recipients"));
  const [seal, setSeal] = useState(false);
  const [open, setOpen] = useState(null);
  const canManage = session.operator.role === "security-officer";
  const recipients = rcps.data || [];
  const current = (docs.data || []).find((d) => d.id === open);

  return (
    <>
      <PageHeader eyebrow="Identity & access" title="Sealed documents"
        subtitle="Master documents encrypted at rest. Only recipients with an ML-KEM key wrap can open them, and every opening creates a uniquely watermarked copy."
        actions={canManage && <Button variant="primary" icon={FileUp} onClick={() => setSeal(true)}>Seal document</Button>} />
      <Card pad={false}>
        <ErrorBox error={docs.error} className="m-4" />
        {docs.loading && !docs.data ? <div className="p-5"><Spinner /></div> : !docs.data?.length ? (
          <Empty icon={FileLock2} title="No sealed documents" action={canManage && <Button variant="primary" icon={FileUp} onClick={() => setSeal(true)}>Seal a document</Button>}>
            Sealed PDFs appear here with their access lists.
          </Empty>
        ) : (
          <Table head={["Document", "Pages", "Recipients", "Sessions", "Sealed", "SHA3-256"]}>
            {docs.data.map((d) => (
              <tr key={d.id} className="cursor-pointer hover:bg-inset" onClick={() => setOpen(d.id)}>
                <td className="td">
                  <div className="flex items-center gap-3">
                    <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/10 text-accent"><FileLock2 className="h-4 w-4" /></span>
                    <div><div className="font-medium">{d.title}</div><div className="font-mono text-[11.5px] text-subtle">{d.id}</div></div>
                  </div>
                </td>
                <td className="td tabular-nums">{d.pages}</td>
                <td className="td">
                  <div className="flex -space-x-1.5">
                    {d.recipients.slice(0, 5).map((rid) => {
                      const r = recipients.find((x) => x.id === rid);
                      return <span key={rid} title={r?.name} className="flex h-6 w-6 items-center justify-center rounded-full bg-inset text-[10px] font-semibold text-muted ring-2 ring-surface">{r ? r.name.split(" ").map((p) => p[0]).slice(0, 2).join("") : "?"}</span>;
                    })}
                    {d.recipients.length > 5 && <span className="flex h-6 w-6 items-center justify-center rounded-full bg-inset text-[10px] ring-2 ring-surface">+{d.recipients.length - 5}</span>}
                    {!d.recipients.length && <span className="text-subtle">—</span>}
                  </div>
                </td>
                <td className="td tabular-nums">{d.sessions}</td>
                <td className="td text-muted"><div>{when(d.created_at)}</div><div className="text-[11.5px] text-subtle">by {d.created_by_name}</div></td>
                <td className="td"><Hash value={d.sha3} n={12} /></td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      <SealModal open={seal} onClose={() => setSeal(false)} recipients={recipients} onDone={() => { setSeal(false); docs.reload(); }} />
      {current && <DocDrawer doc={current} recipients={recipients} canManage={canManage} onClose={() => setOpen(null)} onChanged={docs.reload} />}
    </>
  );
}
