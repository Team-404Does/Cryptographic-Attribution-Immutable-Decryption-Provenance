"""SHA3-256 Merkle tree with inclusion proofs (domain-separated leaves / nodes)."""
from __future__ import annotations

import hashlib


def _h(prefix: bytes, data: bytes) -> bytes:
    return hashlib.sha3_256(prefix + data).digest()


def leaf(data: bytes) -> bytes:
    return _h(b"\x00", data)


def _node(a: bytes, b: bytes) -> bytes:
    return _h(b"\x01", a + b)


def root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return _h(b"\x02", b"")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def proof(leaves: list[bytes], index: int) -> list[dict]:
    path, level, i = [], list(leaves), index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = i ^ 1
        path.append({"hash": level[sib].hex(), "side": "left" if sib < i else "right"})
        level = [_node(level[j], level[j + 1]) for j in range(0, len(level), 2)]
        i //= 2
    return path


def verify_proof(leaf_hash: bytes, path: list[dict], expected_root: bytes) -> bool:
    h = leaf_hash
    for step in path:
        s = bytes.fromhex(step["hash"])
        h = _node(s, h) if step["side"] == "left" else _node(h, s)
    return h == expected_root
