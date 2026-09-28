import React, { useState } from "react";
import { FileSearch, FlaskConical, Loader2, ScanSearch, UploadCloud } from "lucide-react";
import { api } from "../api.js";
import { Button, Card, ErrorBox, Field, PageHeader, useAction, useLoad } from "../components/ui.jsx";
import ReportView from "../components/ReportView.jsx";

const STEPS = ["Pre-processing evidence", "Extracting raster & text channels", "Reed-Solomon recovery", "Resolving on ledger", "Verifying signatures & chain"];

export default function Forensics({ status }) {
  const demo = status?.demo_mode;
  const sess = useLoad(() => (demo ? api.get("/api/sessions") : Promise.resolve([])), [demo]);
  const tfs = useLoad(() => (demo ? api.get("/api/robustness/transforms") : Promise.resolve([])), [demo]);
  const [report, setReport] = useState(null);
  const [preview, setPreview] = useState(null);
  const [sim, setSim] = useState({ session: "", transform: "3" });
  const [drag, setDrag] = useState(false);
  const act = useAction();

  const analyze = (file, previewUrl) => act.run(async () => {
    setReport(null);
    setPreview(previewUrl);
    setReport(await api.upload("/api/forensics/analyze", { file }));
  });
  const onFile = (file) => file && analyze(file, file.type.startsWith("image/") ? URL.createObjectURL(file) : null);
  const simulate = () => act.run(async () => {
    const blob = await api.blob(`/api/sessions/${sim.session}/leak?transform=${sim.transform}`);
    const file = new File([blob], `leak-${sim.session}.jpg`, { type: "image/jpeg" });
    setReport(null);
    setPreview(URL.createObjectURL(blob));
    setReport(await api.upload("/api/forensics/analyze", { file }));
  });

  return (
    <>
      <PageHeader eyebrow="Forensics" title="Leak analysis"
        subtitle="Submit a leaked PDF, screenshot, photo, scan or pasted text. The mark is extracted blindly: the engine is never told who the suspect is." />
      <div className={`grid gap-6 ${demo ? "lg:grid-cols-[1.4fr_1fr]" : ""}`}>
        <label onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files[0]); }}
          className={`card flex min-h-[220px] cursor-pointer flex-col items-center justify-center border-2 border-dashed p-8 text-center transition ${drag ? "border-accent bg-accent/5" : "border-line-strong hover:bg-inset"}`}>
          <input type="file" className="hidden" accept=".pdf,image/*,.txt" onChange={(e) => onFile(e.target.files[0])} />
          <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10 text-accent"><UploadCloud className="h-6 w-6" /></span>
          <div className="mt-3 text-[15px] font-semibold">Drop leaked evidence to analyse</div>
          <div className="mt-1 text-[13px] text-subtle">PDF · PNG / JPEG screenshot, scan or photo · .txt excerpt</div>
          <div className="mt-4 text-[12px] text-subtle">Cropped, rotated or angled captures are aligned automatically against the original pages</div>
        </label>
        {demo && (
          <Card title="Leak simulator" subtitle="Degrade a real recipient copy, then attribute it blindly">
            <div className="space-y-3">
              <Field label="Source decryption session">
                <select className="input" value={sim.session} onChange={(e) => setSim({ ...sim, session: e.target.value })}>
                  <option value="">Choose a session…</option>
                  {(sess.data || []).map((s) => <option key={s.id} value={s.id}>{s.recipient_name} · {s.id}</option>)}
                </select>
              </Field>
              <Field label="Leak transformation">
                <select className="input" value={sim.transform} onChange={(e) => setSim({ ...sim, transform: e.target.value })}>
                  {(tfs.data || []).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                </select>
              </Field>
              <Button variant="primary" className="w-full" icon={FlaskConical} disabled={!sim.session} busy={act.busy} onClick={simulate}>Leak & attribute</Button>
            </div>
          </Card>
        )}
      </div>

      <ErrorBox error={act.error} className="mt-6" />
      {act.busy && (
        <div className="card mt-6 p-6">
          <div className="flex items-center gap-3 text-[14px] font-medium"><Loader2 className="h-5 w-5 animate-spin text-accent" /> Analysing evidence…</div>
          <ol className="mt-4 grid gap-2 sm:grid-cols-5">
            {STEPS.map((s) => <li key={s} className="rounded-lg bg-inset px-3 py-2 text-[12px] text-muted">{s}</li>)}
          </ol>
        </div>
      )}
      {report && <div className="mt-6 animate-rise"><ReportView report={report} preview={preview} /></div>}
      {!report && !act.busy && (
        <div className="mt-6 flex items-center gap-3 rounded-xl border border-line bg-surface px-5 py-4 text-[13px] text-muted">
          <ScanSearch className="h-5 w-5 text-subtle" /> Results appear here: verdict, attributed identity, chain of evidence and a dual-signed report you can export.
          <FileSearch className="ml-auto hidden h-5 w-5 text-subtle md:block" />
        </div>
      )}
    </>
  );
}
