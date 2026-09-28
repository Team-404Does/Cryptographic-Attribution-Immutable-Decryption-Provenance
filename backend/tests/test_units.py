import os

from app.crypto import pqc
from app.ledger import merkle
from app.watermark import payload, text_wm


def test_pqc_roundtrip():
    pk, sk = pqc.kem_keygen()
    ct, ss = pqc.kem_encaps(pk)
    assert pqc.kem_decaps(sk, ct) == ss
    vk, sk2 = pqc.sig_keygen()
    sig = pqc.sign(sk2, b"msg")
    assert pqc.verify(vk, b"msg", sig) and not pqc.verify(vk, b"msh", sig)


KEY = b"k" * 32


def test_payload_corrects_errors():
    wid = os.urandom(6)
    bits = payload.encode(wid, KEY)
    for i in range(0, 4 * 8, 8):   # corrupt 4 whole bytes
        bits[i * 3] ^= 1
    assert payload.decode(bits, KEY)[0] == wid


def test_payload_is_keyed():
    """Without the embedding key a valid frame cannot be produced or read."""
    wid = os.urandom(6)
    assert payload.decode(payload.encode(wid, b"attacker-key" * 3), KEY)[0] is None
    assert payload.decode(payload.encode(wid, KEY), b"attacker-key" * 3)[0] is None


def test_merkle_proofs():
    leaves = [merkle.leaf(bytes([i])) for i in range(7)]
    root = merkle.root(leaves)
    for i in range(7):
        assert merkle.verify_proof(leaves[i], merkle.proof(leaves, i), root)
    assert not merkle.verify_proof(merkle.leaf(b"x"), merkle.proof(leaves, 0), root)


def test_homoglyph_is_visually_neutral():
    wid = os.urandom(6)
    src = "The committee recommends a secure process. " * 20
    marked, _ = text_wm.embed(src, wid, KEY)
    assert marked != src and text_wm.strip(marked) == src
    assert text_wm.extract(marked, KEY)[0] == wid
    assert text_wm.extract(marked, b"other" * 8)[0] is None
