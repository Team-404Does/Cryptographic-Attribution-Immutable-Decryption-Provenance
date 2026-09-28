import React, { useMemo, useState } from "react";
import { Activity, Search } from "lucide-react";
import { api, ago, when } from "../api.js";
import { Badge, Card, Empty, ErrorBox, PageHeader, Spinner, Table, useLoad } from "../components/ui.jsx";

export default function Sessions({ go }) {
  const list = useLoad(() => api.get("/api/sessions"));
  const [q, setQ] = useState("");
  const rows = useMemo(() => (list.data || []).filter((s) =>
    `${s.id} ${s.wm_id} ${s.recipient_name} ${s.doc_title}`.toLowerCase().includes(q.toLowerCase())), [list.data, q]);

  return (
    <>
      <PageHeader eyebrow="Assurance" title="Decryption log"
        subtitle="Every time a document was opened. Each session has its own watermark ID and an ML-DSA-signed record in the ledger."
        actions={<div className="relative w-72"><Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-subtle" />
          <input className="input pl-9" placeholder="Search session, watermark, person…" value={q} onChange={(e) => setQ(e.target.value)} /></div>} />
      <Card pad={false}>
        <ErrorBox error={list.error} className="m-4" />
        {list.loading && !list.data ? <div className="p-5"><Spinner /></div> : !rows.length ? (
          <Empty icon={Activity} title={list.data?.length ? "No matching sessions" : "No decryptions yet"}>
            Recipients open documents from the secure viewer. Each session appears here.
          </Empty>
        ) : (
          <Table head={["Session", "Recipient", "Document", "Watermark ID", "Ledger", "When"]}>
            {rows.map((s) => (
              <tr key={s.id} className="hover:bg-inset">
                <td className="td font-mono text-[12.5px]">{s.id}</td>
                <td className="td font-medium">{s.recipient_name}</td>
                <td className="td text-muted">{s.doc_title}</td>
                <td className="td"><Badge tone="accent"><span className="font-mono">{s.wm_id}</span></Badge></td>
                <td className="td"><button className="link font-mono text-[12.5px]" onClick={() => go("ledger")}>#{s.block_index}</button></td>
                <td className="td text-muted" title={when(s.created_at)}>{ago(s.created_at)}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
