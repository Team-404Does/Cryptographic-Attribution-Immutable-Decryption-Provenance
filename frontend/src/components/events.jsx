import { Ban, FilePlus2, KeyRound, LockOpen, ShieldCheck, Sprout, UserMinus, UserPlus, UserRoundCog, Unlink } from "lucide-react";

export const EVENT_META = {
  genesis: { label: "Genesis", icon: Sprout, tone: "mute" },
  "operator-enrollment": { label: "Operator enrolled", icon: UserRoundCog, tone: "accent" },
  enrollment: { label: "Identity enrolled", icon: UserPlus, tone: "info" },
  revocation: { label: "Identity revoked", icon: UserMinus, tone: "bad" },
  "token-unlock": { label: "Token unlocked", icon: LockOpen, tone: "warn" },
  "document-registration": { label: "Document sealed", icon: FilePlus2, tone: "accent" },
  grant: { label: "Access granted", icon: ShieldCheck, tone: "ok" },
  "access-revocation": { label: "Access revoked", icon: Unlink, tone: "bad" },
  decryption: { label: "Decryption", icon: KeyRound, tone: "info" },
};

export const meta = (t) => EVENT_META[t] || { label: t, icon: Ban, tone: "mute" };

/** One-line human description of a ledger event. `names` maps operator/recipient/document ids to labels. */
export function describe(e, names = {}) {
  const n = (id) => names[id] || id;
  const p = e.body?.payload || {};
  const actor = n(e.body?.operator_id);
  switch (e.type) {
    case "genesis": return `Ledger created with ${e.quorum?.k}-of-${e.quorum?.n} endorsement quorum`;
    case "operator-enrollment": return p.bootstrap ? `${p.name} initialised the installation as security officer` : `${actor} enrolled operator ${p.name} (${p.role})`;
    case "enrollment": return `${actor} enrolled ${p.name} · ${p.employee_id}`;
    case "revocation": return `${actor} revoked ${n(p.recipient_id)} · ${p.reason}`;
    case "token-unlock": return `${actor} unlocked the token of ${n(p.recipient_id)}`;
    case "document-registration": return `${actor} sealed “${p.title}”`;
    case "grant": return `${actor} granted ${n(p.recipient_id)} access to ${n(p.document_id)}`;
    case "access-revocation": return `${actor} revoked access of ${n(p.recipient_id)} to ${n(p.document_id)}`;
    case "decryption": return `${n(e.record?.recipient_id)} decrypted ${n(e.record?.document_id)}`;
    default: return e.type;
  }
}

export const eventTime = (e) => e.body?.at || e.record?.timestamp || e.created_at;
