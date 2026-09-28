import React, { useState } from "react";
import { ArrowLeft, FileCheck2, ScrollText } from "lucide-react";
import { api, ago, when } from "../api.js";
import { Alert, Badge, Button, Card, Empty, ErrorBox, PageHeader, Spinner, Table, useAction, useLoad } from "../components/ui.jsx";
import ReportView, { VERDICT } from "../components/ReportView.jsx";

function VerifyExported() {
  const [res, setRes] = useState(null);
  const act = useAction();
  const onFile = (f) => f && act.run(async () => {
    setRes(null);
    let json;
    try { json = JSON.parse(await f.text()); } catch { throw new Error("not a JSON report"); }
    setRes({ name: f.name, ...(await api.post("/api/reports/verify", json)) });
  });
  return (
    <Card title="Verify an exported report" subtitle="Checks both ML-DSA signatures on a signed JSON evidence package">
      <label className="flex cursor-pointer items-center gap-3 rounded-lg border border-dashed border-line-strong px-4 py-3 hover:bg-inset">
        <input type="file" accept="application/json,.json" className="hidden" onChange={(e) => onFile(e.target.files[0])} />
        <FileCheck2 className="h-5 w-5 text-subtle" />
        <span className="text-[13px] text-muted">Choose a <span className="font-mono">rpt-*.json</span> file…</span>
        {act.busy && <Spinner />}
      </label>
      <ErrorBox error={act.error} className="mt-3" />
      {res && (
        <Alert className="mt-3" tone={res.valid ? "ok" : "bad"} title={res.valid ? "Signatures valid: report unmodified" : "Verification failed: report altered or not issued here"}>
          <span className="font-mono text-[12px]">{res.name} · service {res.service_signature_ok ? "✓" : "✕"} · examiner {res.examiner_signature_ok ? "✓" : "✕"}</span>
        </Alert>
      )}
    </Card>
  );
}

export default function Reports() {
  const list = useLoad(() => api.get("/api/reports"));
  const [open, setOpen] = useState(null);
  const act = useAction();
  const show = (id) => act.run(async () => setOpen(await api.get(`/api/reports/${id}`)));

  if (open) {
    return (
      <>
        <Button variant="ghost" icon={ArrowLeft} className="-ml-2 mb-4" onClick={() => setOpen(null)}>All reports</Button>
        <ReportView report={open} />
      </>
    );
  }
  return (
    <>
      <PageHeader eyebrow="Forensics" title="Evidence reports"
        subtitle="Every analysis produces a canonical JSON evidence package, signed by the forensic service key and the examiner's own token, plus a PDF rendering." />
      <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
        <Card pad={false}>
          <ErrorBox error={list.error || act.error} className="m-4" />
          {list.loading && !list.data ? <div className="p-5"><Spinner /></div> : !list.data?.length ? <Empty icon={ScrollText} title="No reports yet">Run a leak analysis to create the first report.</Empty> : (
            <Table head={["Report", "Verdict", "Watermark", "Examiner", "Created"]}>
              {list.data.map((r) => {
                const v = VERDICT[r.verdict];
                return (
                  <tr key={r.id} className="cursor-pointer hover:bg-inset" onClick={() => show(r.id)}>
                    <td className="td font-mono text-[12.5px]">{r.id}</td>
                    <td className="td"><Badge tone={v.tone}><v.icon className="h-3 w-3" />{v.label}</Badge></td>
                    <td className="td font-mono text-[12px] text-muted">{r.wm_id || "—"}</td>
                    <td className="td text-muted">{r.examiner || "—"}</td>
                    <td className="td text-muted" title={when(r.created_at)}>{ago(r.created_at)}</td>
                  </tr>
                );
              })}
            </Table>
          )}
        </Card>
        <VerifyExported />
      </div>
    </>
  );
}
