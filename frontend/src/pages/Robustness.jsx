import React, { useState } from "react";
import { CheckCircle2, FlaskConical, XCircle } from "lucide-react";
import { api } from "../api.js";
import { Badge, Button, Card, Empty, ErrorBox, Field, PageHeader, Spinner, Table, useAction, useLoad } from "../components/ui.jsx";

export default function Robustness() {
  const sess = useLoad(() => api.get("/api/sessions"));
  const [sid, setSid] = useState("");
  const [res, setRes] = useState(null);
  const act = useAction();
  const run = () => act.run(async () => { setRes(null); setRes(await api.post(`/api/sessions/${sid}/robustness`)); });
  const raster = res?.results.filter((r) => r.channel === "raster") || [];
  const text = res?.results.filter((r) => r.channel === "text") || [];
  const maxConf = Math.max(1, ...raster.map((r) => r.confidence));

  return (
    <>
      <PageHeader eyebrow="Forensics · demo" title="Adversarial robustness lab"
        subtitle="Scripted leak transformations are applied to a real recipient copy, then the mark is extracted blindly. Signal is the bit-correlation margin over the noise floor. Above about 4 decodes reliably." />
      <Card className="mb-6">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[320px] flex-1">
            <Field label="Decryption session under test">
              <select className="input" value={sid} onChange={(e) => setSid(e.target.value)}>
                <option value="">Choose…</option>
                {(sess.data || []).map((s) => <option key={s.id} value={s.id}>{s.recipient_name} · {s.id} · wm {s.wm_id}</option>)}
              </select>
            </Field>
          </div>
          <Button variant="primary" icon={FlaskConical} disabled={!sid} busy={act.busy} onClick={run}>Run adversarial suite</Button>
        </div>
      </Card>
      <ErrorBox error={act.error} />
      {act.busy && <div className="flex items-center gap-2 text-[13px] text-muted"><Spinner /> Running adversarial suite…</div>}
      {!res && !act.busy && <Card><Empty icon={FlaskConical} title="Choose a session and run the suite" /></Card>}
      {res && (
        <div className="space-y-6 animate-rise">
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="card p-4"><div className="text-[12.5px] text-muted">Recovered</div><div className="mt-1 text-[26px] font-semibold tabular-nums">{res.passed}<span className="text-[16px] text-subtle"> / {res.total}</span></div></div>
            <div className="card p-4"><div className="text-[12.5px] text-muted">Raster channel</div><div className="mt-1 text-[26px] font-semibold tabular-nums">{raster.filter((r) => r.success).length}<span className="text-[16px] text-subtle"> / {raster.length}</span></div></div>
            <div className="card p-4"><div className="text-[12.5px] text-muted">Expected watermark</div><div className="mt-2 font-mono text-[15px] text-accent">{res.expected_watermark}</div></div>
          </div>
          <Card title="Image transformations" pad={false}>
            <Table head={["Transformation", { label: "Signal", className: "w-1/4" }, "Alignment", "Recovered", "Result"]}>
              {raster.map((r) => (
                <tr key={r.transform}>
                  <td className="td">{r.transform}</td>
                  <td className="td">
                    <div className="flex items-center gap-3">
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-inset ring-1 ring-line">
                        <div className={`h-full rounded-full ${r.success ? "bg-accent" : "bg-bad"}`} style={{ width: `${Math.max(3, (r.confidence / maxConf) * 100)}%` }} />
                      </div>
                      <span className="w-10 text-right font-mono text-[12px] text-muted">{r.confidence}</span>
                    </div>
                  </td>
                  <td className="td">{r.alignment === "homography" ? <Badge tone="info">registered</Badge> : r.alignment === "full-page" ? <Badge>full page</Badge> : <span className="text-subtle">—</span>}</td>
                  <td className="td font-mono text-[12px] text-muted">{r.recovered || "—"}{r.rs_corrected_bytes > 0 && <span className="text-warn"> · RS fixed {r.rs_corrected_bytes}</span>}</td>
                  <td className="td">{r.success ? <Badge tone="ok"><CheckCircle2 className="h-3 w-3" />Attributed</Badge> : <Badge tone="bad"><XCircle className="h-3 w-3" />Lost</Badge>}</td>
                </tr>
              ))}
            </Table>
          </Card>
          <Card title="Text transformations" pad={false}>
            <Table head={["Transformation", "Full frames", "Recovered", "Result"]}>
              {text.map((r) => (
                <tr key={r.transform}>
                  <td className="td">{r.transform}</td>
                  <td className="td font-mono text-[12px]">{r.confidence}</td>
                  <td className="td font-mono text-[12px] text-muted">{r.recovered || "—"}</td>
                  <td className="td">{r.success ? <Badge tone="ok"><CheckCircle2 className="h-3 w-3" />Attributed</Badge> : <Badge tone="bad"><XCircle className="h-3 w-3" />Lost</Badge>}</td>
                </tr>
              ))}
            </Table>
          </Card>
          <p className="text-[12.5px] leading-relaxed text-subtle">
            When blind extraction fails, the evidence is registered onto the original page with ORB features and a RANSAC homography
            (“registered”). That recovers crops, rotations, perspective photos and viewer screenshots. Known limits: very small, heavily
            downscaled fragments carry too little signal, a text excerpt needs at least 128 eligible characters, and retyping removes homoglyphs.
          </p>
        </div>
      )}
    </>
  );
}
