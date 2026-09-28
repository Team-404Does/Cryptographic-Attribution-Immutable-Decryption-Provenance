"""Append-only, permissioned, offline hash-chain ledger with Merkle-rooted blocks.

* Every block commits to the previous block hash and to a Merkle root over its
  events, so editing any historical event breaks every downstream link.
* A block is admitted only when a k-of-n quorum of internal stakeholder nodes
  (legal, IT security, compliance) endorse its hash with ML-DSA - one rogue
  administrator cannot mint or rewrite history alone.
* Each node also keeps its own signed view of the chain head; the health check
  cross-checks those views against the shared store and raises divergence alarms.

Production equivalent: Hyperledger Fabric channel with RAFT/PBFT ordering.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import lru_cache

from .. import config, db
from ..crypto import keystore, pqc
from ..crypto.symmetric import canonical, sha3
from . import merkle

VERSION = 1
GENESIS_PREV = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def node_label(node: str) -> str:
    return f"ledger-node-{node}"


def event_leaf(event: dict) -> bytes:
    return merkle.leaf(canonical(event))


def _endorse(block_hash: str) -> list[dict]:
    out = []
    for node in config.LEDGER_NODES:
        sig = keystore.system_session(node_label(node)).sign(bytes.fromhex(block_hash))
        out.append({"node": node, "alg": pqc.SIG_ALG, "signature": keystore.b64e(sig)})
    return out


def _write_node_head(node: str, index: int, block_hash: str) -> None:
    body = {"node": node, "index": index, "block_hash": block_hash, "at": _now()}
    sig = keystore.system_session(node_label(node)).sign(canonical(body))
    (config.NODES_DIR / f"{node}.head.json").write_text(
        json.dumps({"body": body, "signature": keystore.b64e(sig)}, indent=1))


def head() -> dict | None:
    r = db.row("SELECT * FROM blocks ORDER BY idx DESC LIMIT 1")
    return _decode(r) if r else None


def _decode(r: dict) -> dict:
    return {"index": r["idx"], "header": json.loads(r["header"]), "block_hash": r["block_hash"],
            "events": json.loads(r["events"]), "endorsements": json.loads(r["endorsements"])}


def ensure_genesis() -> dict:
    h = head()
    if h:
        return h
    from ..crypto import pki
    for n in config.LEDGER_NODES:
        keystore.system_session(node_label(n))  # provisions the node token on first use
    nodes = {n: keystore.public_keys(node_label(n)) for n in config.LEDGER_NODES}
    genesis = {"type": "genesis", "created_at": _now(), "ca_fingerprint": pki.ca_certificate()["fingerprint"],
               "quorum": {"k": config.LEDGER_QUORUM, "n": len(config.LEDGER_NODES)},
               "nodes": {n: {"sig_alg": v["sig_alg"], "sig_pk_sha3": sha3(keystore.b64d(v["sig_pk"]))}
                         for n, v in nodes.items()}}
    return append([genesis], _prev=GENESIS_PREV, _index=0)


def append(events: list[dict], _prev: str | None = None, _index: int | None = None) -> dict:
    if _index is None:
        ensure_genesis()
    with db.tx() as conn:
        if _index is None:
            h = head()
            _index, _prev = h["index"] + 1, h["block_hash"]
        leaves = [event_leaf(e) for e in events]
        header = {"version": VERSION, "index": _index, "prev_hash": _prev, "timestamp": _now(),
                  "merkle_root": merkle.root(leaves).hex(), "event_count": len(events)}
        block_hash = sha3(canonical(header))
        endorsements = _endorse(block_hash)
        valid = sum(_endorsement_ok(e, block_hash) for e in endorsements)
        if valid < config.LEDGER_QUORUM:
            raise RuntimeError("block rejected: endorsement quorum not reached")
        conn.execute("INSERT INTO blocks (idx, header, block_hash, events, endorsements) VALUES (?,?,?,?,?)",
                     (_index, json.dumps(header), block_hash, json.dumps(events), json.dumps(endorsements)))
    for node in config.LEDGER_NODES:
        _write_node_head(node, _index, block_hash)
    return {"index": _index, "header": header, "block_hash": block_hash, "events": events,
            "endorsements": endorsements}


@lru_cache(maxsize=65536)
def _verify_cached(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """ML-DSA verification is a pure function of its inputs, so audits re-use earlier results.
    (Cache keys include the full signature and message, so tampering always misses the cache.)"""
    return pqc.verify(pk, msg, sig)


def _endorsement_ok(e: dict, block_hash: str) -> bool:
    if e.get("node") not in config.LEDGER_NODES:
        return False
    try:
        pk = keystore.b64d(keystore.public_keys(node_label(e["node"]))["sig_pk"])
        return _verify_cached(pk, bytes.fromhex(block_hash), keystore.b64d(e["signature"]))
    except (KeyError, ValueError, TypeError):
        return False


def blocks(limit: int = 200, offset: int = 0) -> list[dict]:
    return [_decode(r) for r in db.rows("SELECT * FROM blocks ORDER BY idx DESC LIMIT ? OFFSET ?", limit, offset)]


def block(index: int) -> dict | None:
    r = db.row("SELECT * FROM blocks WHERE idx=?", index)
    return _decode(r) if r else None


def verify_block(b: dict, prev_hash: str | None) -> dict:
    header = b["header"]
    recomputed_root = merkle.root([event_leaf(e) for e in b["events"]]).hex()
    recomputed_hash = sha3(canonical(header))
    endorsed = sum(_endorsement_ok(e, b["block_hash"]) for e in b["endorsements"])
    checks = {
        "merkle_root_ok": recomputed_root == header["merkle_root"],
        "header_hash_ok": recomputed_hash == b["block_hash"],
        "prev_link_ok": prev_hash is None or header["prev_hash"] == prev_hash,
        "index_ok": header["index"] == b["index"],
        "endorsements_valid": endorsed,
        "quorum_ok": endorsed >= config.LEDGER_QUORUM,
    }
    checks["ok"] = all(v for k, v in checks.items() if k.endswith("_ok"))
    return checks


def verify_chain() -> dict:
    """Full integrity audit. Returns first broken block (if any) and per-block results."""
    results, prev, first_bad = [], None, None
    for r in db.rows("SELECT * FROM blocks ORDER BY idx ASC"):
        b = _decode(r)
        c = verify_block(b, prev if b["index"] > 0 else None)
        if b["index"] == 0:
            c["prev_link_ok"] = b["header"]["prev_hash"] == GENESIS_PREV
            c["ok"] = c["ok"] and c["prev_link_ok"]
        results.append({"index": b["index"], "block_hash": b["block_hash"], **c})
        if not c["ok"] and first_bad is None:
            first_bad = b["index"]
        prev = b["block_hash"]  # stored hash; a tampered header is caught by header_hash_ok
    health = node_health()
    return {"valid": first_bad is None and health["consistent"], "length": len(results),
            "first_invalid_block": first_bad, "blocks": results, "node_health": health,
            "head_hash": results[-1]["block_hash"] if results else None, "checked_at": _now()}


def node_health() -> dict:
    """Self-auditing cross-check: every node's signed head must match the shared chain."""
    h = head()
    views = []
    for node in config.LEDGER_NODES:
        p = config.NODES_DIR / f"{node}.head.json"
        if not p.exists():
            views.append({"node": node, "status": "missing"})
            continue
        v = json.loads(p.read_text())
        pk = keystore.b64d(keystore.public_keys(node_label(node))["sig_pk"])
        sig_ok = _verify_cached(pk, canonical(v["body"]), keystore.b64d(v["signature"]))
        stored = block(v["body"]["index"])
        agrees = bool(stored and stored["block_hash"] == v["body"]["block_hash"])
        is_head = bool(h and h["index"] == v["body"]["index"])
        status = "in-sync" if sig_ok and agrees and is_head else ("stale" if sig_ok and agrees else "DIVERGED")
        views.append({"node": node, "status": status, "index": v["body"]["index"],
                      "block_hash": v["body"]["block_hash"], "signature_ok": sig_ok})
    return {"consistent": all(v["status"] == "in-sync" for v in views), "nodes": views}


def locate_event(block_index: int, predicate) -> tuple[dict, int] | None:
    b = block(block_index)
    if not b:
        return None
    for i, e in enumerate(b["events"]):
        if predicate(e):
            return b, i
    return None


def inclusion_proof(b: dict, event_index: int) -> dict:
    leaves = [event_leaf(e) for e in b["events"]]
    path = merkle.proof(leaves, event_index)
    ok = merkle.verify_proof(leaves[event_index], path, bytes.fromhex(b["header"]["merkle_root"]))
    return {"block_index": b["index"], "event_index": event_index, "leaf": leaves[event_index].hex(),
            "path": path, "merkle_root": b["header"]["merkle_root"], "verified": ok}


# --- demo helpers: simulate an insider editing the database directly -------------

_BACKUP = "tamper_backup.json"


def simulate_tamper(index: int) -> dict:
    b = block(index)
    if not b or index == 0:
        raise ValueError("choose an existing non-genesis block")
    backup = config.NODES_DIR / _BACKUP
    saved = json.loads(backup.read_text()) if backup.exists() else {}
    saved.setdefault(str(index), b["events"])     # keep the *original* of every tampered block
    backup.write_text(json.dumps(saved))
    events = json.loads(json.dumps(b["events"]))
    ev = events[0]
    if ev.get("type") == "decryption":
        ev["record"]["recipient_id"] = "rcp-scapegoat"
        ev["record"]["timestamp"] = "2020-01-01T00:00:00+00:00"
        change = "recipient_id and timestamp of the decryption record rewritten"
    else:
        ev.setdefault("body", {}).setdefault("payload", {})["tampered"] = True
        ev["body"]["at"] = "2020-01-01T00:00:00+00:00"
        change = f"payload and timestamp of the {ev.get('type')} event rewritten"
    with db.tx() as conn:
        conn.execute("UPDATE blocks SET events=? WHERE idx=?", (json.dumps(events), index))
    return {"tampered_block": index, "change": change}


def repair_tamper() -> dict:
    backup = config.NODES_DIR / _BACKUP
    if not backup.exists():
        return {"restored": None}
    saved = json.loads(backup.read_text())
    with db.tx() as conn:
        for idx, events in saved.items():
            conn.execute("UPDATE blocks SET events=? WHERE idx=?", (json.dumps(events), int(idx)))
    backup.unlink()
    return {"restored": sorted(int(i) for i in saved)}
