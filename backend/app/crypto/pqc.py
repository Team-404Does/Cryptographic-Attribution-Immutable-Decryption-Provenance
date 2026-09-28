"""Post-quantum primitives: ML-KEM (FIPS 203) and ML-DSA (FIPS 204).

Uses liboqs (Open Quantum Safe) through `oqs` when it is installed, and falls
back to the pure-Python FIPS reference implementations (kyber-py /
dilithium-py) so the prototype runs on any air-gapped machine without a
native build. Both backends produce standard-sized keys/ciphertexts/signatures.
"""
from __future__ import annotations

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"

try:  # pragma: no cover - depends on native liboqs being present
    import oqs  # type: ignore

    BACKEND = f"liboqs {oqs.oqs_version()}"

    def kem_keygen() -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(KEM_ALG) as k:
            pk = k.generate_keypair()
            return pk, k.export_secret_key()

    def kem_encaps(pk: bytes) -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(KEM_ALG) as k:
            ct, ss = k.encap_secret(pk)
            return ct, ss

    def kem_decaps(sk: bytes, ct: bytes) -> bytes:
        with oqs.KeyEncapsulation(KEM_ALG, secret_key=sk) as k:
            return k.decap_secret(ct)

    def sig_keygen() -> tuple[bytes, bytes]:
        with oqs.Signature(SIG_ALG) as s:
            pk = s.generate_keypair()
            return pk, s.export_secret_key()

    def sign(sk: bytes, msg: bytes) -> bytes:
        with oqs.Signature(SIG_ALG, secret_key=sk) as s:
            return s.sign(msg)

    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        with oqs.Signature(SIG_ALG) as s:
            return bool(s.verify(msg, sig, pk))

except Exception:  # ImportError, or liboqs shared library missing
    from dilithium_py.ml_dsa import ML_DSA_65
    from kyber_py.ml_kem import ML_KEM_768

    BACKEND = "pure-python FIPS 203/204 reference (kyber-py, dilithium-py)"

    def kem_keygen() -> tuple[bytes, bytes]:
        return ML_KEM_768.keygen()          # (encapsulation key, decapsulation key)

    def kem_encaps(pk: bytes) -> tuple[bytes, bytes]:
        ss, ct = ML_KEM_768.encaps(pk)
        return ct, ss

    def kem_decaps(sk: bytes, ct: bytes) -> bytes:
        return ML_KEM_768.decaps(sk, ct)

    def sig_keygen() -> tuple[bytes, bytes]:
        return ML_DSA_65.keygen()

    def sign(sk: bytes, msg: bytes) -> bytes:
        return ML_DSA_65.sign(sk, msg)

    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            return bool(ML_DSA_65.verify(pk, msg, sig))
        except Exception:
            return False


def info() -> dict:
    return {"kem": KEM_ALG, "signature": SIG_ALG, "backend": BACKEND}
