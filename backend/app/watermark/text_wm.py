"""Homoglyph text-channel watermark.

Every *eligible* Latin character (one that has a visually equivalent Unicode
code point) carries one frame bit: the original glyph encodes 0, its homoglyph
encodes 1. The frame is repeated back-to-back across the text, so a partial
copy/paste still carries complete frames. The decoder tries every frame phase,
majority-votes repetitions and lets Reed-Solomon fix the rest. The frame is
keyed (see payload.py), so a valid mark cannot be written without the
installation's embedding key.

Limitation: homoglyphs are trivially normalised (Unicode confusable folding) or
lost when text is retyped; the raster channel is the robust one.
"""
from __future__ import annotations

import numpy as np

from . import payload

# Latin -> visually identical Cyrillic / Greek code points
HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р",
    "x": "х", "y": "у", "i": "і", "j": "ј", "s": "ѕ",
    "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н",
    "K": "К", "M": "М", "O": "О", "P": "Р", "T": "Т",
    "X": "Х", "Y": "Υ",
}
REVERSE = {v: k for k, v in HOMOGLYPHS.items()}
N = payload.FRAME_BITS


def capacity(text: str) -> int:
    return sum(1 for ch in text if ch in HOMOGLYPHS or ch in REVERSE)


def embed(text: str, wm_id: bytes, key: bytes, start: int = 0) -> tuple[str, int]:
    """Embed the frame into text. `start` continues the bit stream across calls
    (e.g. across text spans of a page). Returns (marked_text, next_position)."""
    bits = payload.encode(wm_id, key)
    out, pos = [], start
    for ch in text:
        base = REVERSE.get(ch, ch)
        if base in HOMOGLYPHS:
            out.append(HOMOGLYPHS[base] if bits[pos % N] else base)
            pos += 1
        else:
            out.append(ch)
    return "".join(out), pos


def strip(text: str) -> str:
    return "".join(REVERSE.get(ch, ch) for ch in text)


def extract(text: str, key: bytes) -> tuple[bytes | None, int, int]:
    """Returns (wm_id, frames_observed, phase). Tries every phase so that
    excerpts starting mid-frame still decode."""
    raw = [1 if ch in REVERSE else 0 for ch in text if ch in HOMOGLYPHS or ch in REVERSE]
    if len(raw) < N or not any(raw):
        return None, 0, -1
    stream = np.array(raw, dtype=np.int32)
    frames = len(stream) // N
    for phase in range(N):
        idx = (np.arange(len(stream)) + phase) % N
        ones = np.bincount(idx, weights=stream, minlength=N)
        tot = np.bincount(idx, minlength=N)
        bits = (ones * 2 > tot).astype(np.uint8)
        wm_id, _ = payload.decode(bits, key)
        if wm_id is not None:
            return wm_id, frames, phase
    return None, frames, -1
