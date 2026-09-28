import React from "react";
import { AlertTriangle, CheckCircle2, CircleDashed, FileDown, FileJson, ShieldAlert, ShieldCheck, ShieldQuestion, XCircle } from "lucide-react";
import { api, saveBlob, when } from "../api.js";
import { Alert, Badge, Button, Card, CheckRow, Hash, KV, Table, useAction } from "./ui.jsx";

export const VERDICT = {
  ATTRIBUTED: { tone: "ok", label: "Leak attributed", icon: ShieldCheck },
  ATTRIBUTED_WITH_WARNINGS: { tone: "warn", label: "Attributed, with warnings", icon: AlertTriangle },
  EVIDENCE_COMPROMISED: { tone: "bad", label: "Ledger evidence compromised", icon: ShieldAlert },
  UNKNOWN_WATERMARK: { tone: "warn", label: "Unknown watermark", icon: ShieldQuestion },
  NO_WATERMARK: { tone: "mute", label: "No watermark found", icon: CircleDashed },
};

function Stage({ ok, label, detail, last }) {
  const I = ok === null ? CircleDashed : ok ? CheckCircle2 : XCircle;
  return (
    <li className="relative flex-1">
      {!last && <span className={`absolute left-[calc(50%+14px)] right-[calc(-50%+14px)] top-3 h-px ${ok ? "bg-ok/50" : "bg-line-strong"}`} />}
      <div className="flex flex-col items-center text-center">
        <I className={`relative h-6 w-6 rounded-full bg-surface ${ok === null ? "text-subtle" : ok ? "text-ok" : "text-bad"}`} />
        <div className="mt-2 text-[12.5px] font-medium">{label}</div>
        <div className="mt-0.5 text-[11.5px] text-subtle">{detail}</div>
      </div>
    </li>
  );
}

export default function ReportView({ report, preview }) {
  const v = VERDICT[report.verdict] || VERDICT.NO_WATERMARK;
  const c = report.verification;
  const act = useAction();
  const ex = report.extraction;
  const pdf = () => act.run(() => api.download(`/api/reports/${report.report_id}/pdf`, `${report.report_id}.pdf`));
  const json = () => saveBlob(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }), `${report.report_id}.json`);

  const stages = [
    [!!ex.watermark_id, "Extraction", `${ex.agreeing_channels}/${ex.channels.length} channels`],
    [!!ex.watermark_id, "ECC recovery", ex.watermark_id ? "RS(16,8) decoded" : "no valid frame"],
    [report.attribution ? true : ex.watermark_id ? false : null, "Ledger lookup", report.ledger?.block_index != null ? `block #${report.ledger.block_index}` : "—"],
    [c ? c.ml_dsa_signature_ok && c.record_hash_ok : null, "Signature", c ? (c.ml_dsa_signature_ok ? "ML-DSA valid" : "invalid") : "—"],
    [c ? c.chain_integrity_ok && c.block_integrity_ok : null, "Chain audit", c ? (c.chain_integrity_ok ? "consistent" : "failed") : "—"],
  ];

  return (
    <div className="space-y-6">
      <div className={`card overflow-hidden ${v.tone === "ok" ? "border-ok/30" : v.tone === "bad" ? "border-bad/40" : v.tone === "warn" ? "border-warn/40" : ""}`}>
        <div className="flex flex-wrap items-start gap-4 p-5">
          <span className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl ${v.tone === "mute" ? "bg-inset text-subtle" : `bg-${v.tone}/10 text-${v.tone}`}`}><v.icon className="h-6 w-6" /></span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-[17px] font-semibold">{v.label}</h2>
              <Badge tone={v.tone}>{report.verdict}</Badge>
            </div>
            <p className="mt-1 max-w-3xl text-[13.5px] leading-relaxed text-muted">{report.summary}</p>
            <div className="mt-2 text-[12px] text-subtle">Report {report.report_id} · {when(report.generated_at)} · examiner {report.examiner?.name}</div>
          </div>
          <div className="flex gap-2">
            <Button icon={FileDown} busy={act.busy} onClick={pdf}>Evidence PDF</Button>
            <Button icon={FileJson} onClick={json}>Signed JSON</Button>
          </div>
        </div>
        <ol className="flex border-t border-line bg-inset px-4 py-4">
          {stages.map(([ok, l, d], i) => <Stage key={l} ok={ok} label={l} detail={d} last={i === stages.length - 1} />)}
        </ol>
      </div>

      {(report.warnings || []).map((w, i) => <Alert key={i} tone="warn">{w}</Alert>)}

      {report.attribution && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Card title="Attributed identity" subtitle="Taken from the CA-signed certificate, not from editable database fields">
            <div className="mb-4 flex items-center gap-3">
              <span className="flex h-11 w-11 items-center justify-center rounded-full bg-accent/10 text-[14px] font-semibold text-accent">
                {(report.attribution.recipient_name || "?").split(" ").map((p) => p[0]).slice(0, 2).join("")}
              </span>
              <div>
                <div className="text-[15px] font-semibold">{report.attribution.recipient_name}</div>
                <div className="font-mono text-[12px] text-subtle">{report.attribution.employee_id} · {report.attribution.recipient_id}</div>
              </div>
              <Badge tone={report.attribution.identity_status === "active" ? "ok" : "bad"} className="ml-auto">{report.attribution.identity_status}</Badge>
            </div>
            <KV cols={2} rows={[
              ["Department", report.attribution.department], ["Clearance", report.attribution.clearance],
              ["Decryption session", <span className="font-mono">{report.attribution.session_id}</span>],
              ["Decrypted at", when(report.attribution.decrypted_at)],
              ["Document", <span className="font-mono">{report.attribution.document_id}</span>],
              ["Certificate serial", <span className="font-mono">{report.attribution.cert_serial}</span>],
              ["Device fingerprint", <Hash value={report.attribution.device_fingerprint} n={16} />],
              ["Enrolment approved by", report.enrollment?.found ? `${report.enrollment.approved_by} · block #${report.enrollment.block_index}` : "not found"],
            ]} />
          </Card>
          <Card title="Chain of evidence" subtitle="Each check is independently re-verifiable from the signed JSON">
            <div className="-my-2 divide-y divide-line">
              <CheckRow ok={c.record_hash_ok} label="Decryption record hash recomputes (SHA3-256)" />
              <CheckRow ok={c.ml_dsa_signature_ok} label="Recipient's ML-DSA-65 signature is valid" detail={report.event?.signature?.slice(0, 56) + "…"} />
              <CheckRow ok={c.certificate.valid} label="Certificate chains to the offline root and was valid at decryption time" detail={`serial ${c.certificate.serial ?? "—"}`} />
              <CheckRow ok={c.cert_fingerprint_matches_record} label="Certificate is bound to the signed record" />
              <CheckRow ok={c.enrollment_ok} label="Identity enrolment signed by an authorised security officer" />
              <CheckRow ok={c.block_integrity_ok} label="Ledger block intact (header, Merkle root, 2-of-3 quorum)" />
              <CheckRow ok={c.merkle_inclusion_ok} label="Merkle inclusion proof for the event" detail={`${report.ledger.inclusion_proof.path.length} sibling hash(es) → ${report.ledger.header.merkle_root.slice(0, 24)}…`} />
              <CheckRow ok={c.chain_integrity_ok} label="Full chain audit and node consensus" detail={report.ledger.first_invalid_block != null ? `first invalid block #${report.ledger.first_invalid_block}` : `${report.ledger.chain_length} blocks consistent`} />
            </div>
          </Card>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2" title="Extraction channels" pad={false}>
          <Table head={["Channel", "Location", "Watermark ID", "Signal"]}>
            {ex.channels.map((ch, i) => (
              <tr key={i}>
                <td className="td font-medium">{ch.channel}</td>
                <td className="td text-muted">{ch.location}</td>
                <td className="td">{ch.wm_id ? <Badge tone={ch.wm_id === ex.watermark_id ? "accent" : "warn"}><span className="font-mono">{ch.wm_id}</span></Badge> : <Badge>none</Badge>}</td>
                <td className="td font-mono text-[11.5px] text-subtle">{Object.entries(ch.detail).map(([k, x]) => `${k}=${x}`).join("  ")}</td>
              </tr>
            ))}
          </Table>
        </Card>
        <Card title="Evidence item">
          {preview && <img src={preview} alt="Submitted evidence" className="mb-4 max-h-60 w-full rounded-lg border border-line bg-white object-contain" />}
          <KV rows={[["File", report.evidence.filename], ["Type", report.evidence.type], ["Size", `${report.evidence.size.toLocaleString()} bytes`],
            ["SHA3-256", <Hash value={report.evidence.sha3} n={20} />]]} />
        </Card>
      </div>

      <Card title="Report signatures">
        <KV cols={2} rows={[["Service key", `${report.report_signature.signer} · ${report.report_signature.alg}`],
          ["Examiner", `${report.examiner?.name} (${report.report_signature.examiner_id})`],
          ["Report SHA3-256", <Hash value={report.report_signature.report_sha3} full />],
          ["Service signature", <Hash value={report.report_signature.signature} n={40} />]]} />
      </Card>
    </div>
  );
}
