"""Blind spread-spectrum raster watermark.

The page is divided into CELL x CELL pixel cells on a canonical grid (the page
is always resized to CANON_W pixels wide before embedding / extraction, so the
grid survives screenshots taken at other resolutions). Every cell carries one
frame bit, modulated onto a keyed pseudo-random +/-1 pattern made of
BLOCK x BLOCK pixel chips (coarse enough to survive JPEG and rescaling).
Bits are scattered over the whole page with a keyed permutation, so each bit
is repeated many times at many locations (crop / damage tolerance), and the
decoder sums the per-cell correlations before hard-deciding each bit.

The pattern depends only on the system embedding key, never on the session,
so extraction is blind: the recovered frame *is* the session watermark ID.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache

import numpy as np
from PIL import Image
from scipy.ndimage import uniform_filter

from . import payload

CANON_W = 1240          # A4 width at 150 dpi
CELL = 16               # pixels per cell edge
BLOCK = 4               # chip size inside a cell
AMPLITUDE = 3.0         # grey levels (0-255) - below casual visibility
HEADROOM = 4.0          # keep paper white slightly below 255 so +delta is not clipped


def _rng(key: bytes, label: str, h: int, w: int) -> np.random.Generator:
    seed = hashlib.shake_256(key + label.encode() + f"{h}x{w}".encode()).digest(32)
    return np.random.default_rng(np.frombuffer(seed, dtype=np.uint64))


@lru_cache(maxsize=32)
def _layout(key: bytes, h: int, w: int, nbits: int):
    """Chip pattern (h, w) of +/-1 and per-cell bit index map (h//CELL, w//CELL)."""
    rng = _rng(key, "layout", h, w)
    cy, cx = h // CELL, w // CELL
    chips = rng.choice(np.array([-1.0, 1.0], dtype=np.float32), size=(h // BLOCK, w // BLOCK))
    pn = np.kron(chips, np.ones((BLOCK, BLOCK), dtype=np.float32))
    ncell = cy * cx
    order = rng.permutation(ncell)
    bit_of_cell = np.empty(ncell, dtype=np.int32)
    bit_of_cell[order] = np.arange(ncell) % nbits
    return pn, bit_of_cell.reshape(cy, cx)


def canonical_size(w: int, h: int) -> tuple[int, int]:
    ch = int(round(h * CANON_W / w))
    return CANON_W, ch - ch % CELL


def to_canonical(img: Image.Image) -> np.ndarray:
    """Greyscale float array resized to the canonical grid."""
    g = img.convert("L")
    cw, ch = canonical_size(*g.size)
    g = g.resize((cw, ch), Image.LANCZOS)
    return np.asarray(g, dtype=np.float32)


def _grid_view(a: np.ndarray, cy: int, cx: int) -> np.ndarray:
    return a[: cy * CELL, : cx * CELL].reshape(cy, CELL, cx, CELL)


def embed(img: Image.Image, wm_id: bytes, key: bytes, amplitude: float = AMPLITUDE) -> Image.Image:
    """Embed wm_id into an RGB page image. Output keeps the input resolution."""
    rgb = img.convert("RGB")
    ow, oh = rgb.size
    cw, ch = canonical_size(ow, oh)
    bits = payload.encode(wm_id, key)
    pn, bmap = _layout(key, ch, cw, len(bits))
    signs = (bits.astype(np.float32) * 2 - 1)[bmap]            # (cy, cx)
    cy, cx = bmap.shape
    delta = np.zeros((ch, cw), dtype=np.float32)
    _grid_view(delta, cy, cx)[:] = (
        _grid_view(pn, cy, cx) * signs[:, None, :, None] * amplitude
    )
    if (cw, ch) != (ow, oh):
        delta = np.asarray(Image.fromarray(delta, mode="F").resize((ow, oh), Image.BILINEAR))
    arr = np.asarray(rgb, dtype=np.float32)
    arr = arr * ((255.0 - HEADROOM) / 255.0) + HEADROOM / 2
    arr = arr + delta[:, :, None]
    return Image.fromarray(np.clip(np.rint(arr), 0, 255).astype(np.uint8), "RGB")


@dataclass
class Extraction:
    wm_id: bytes | None
    corrected_bytes: int
    confidence: float       # mean |bit correlation| / noise std; > ~4 is a strong detection
    bit_errors_hint: int    # number of weak (low-margin) bits


def _soft_bits(g: np.ndarray, key: bytes, nbits: int, valid: np.ndarray | None = None) -> np.ndarray:
    """Per-bit mean correlation. `valid` (cells grid, bool) restricts decoding to cells actually
    covered by the evidence - e.g. after registering a cropped screenshot onto the page."""
    ch, cw = g.shape
    pn, bmap = _layout(key, ch, cw, nbits)
    resid = g - uniform_filter(g, size=BLOCK * 2 + 1)            # suppress host content
    resid = np.clip(resid, -12, 12)                              # tame text edges
    cy, cx = bmap.shape
    corr = (_grid_view(resid, cy, cx) * _grid_view(pn, cy, cx)).sum(axis=(1, 3))
    w = np.ones_like(corr) if valid is None else valid[:cy, :cx].astype(np.float64)
    soft = np.bincount(bmap.ravel(), weights=(corr * w).ravel(), minlength=nbits)
    counts = np.bincount(bmap.ravel(), weights=w.ravel(), minlength=nbits)
    return soft / np.maximum(counts, 1)


def extract_array(g: np.ndarray, key: bytes, valid: np.ndarray | None = None) -> Extraction:
    """Decode a greyscale page already on the canonical grid."""
    soft = _soft_bits(g, key, payload.FRAME_BITS, valid)
    bits = (soft > 0).astype(np.uint8)
    wm_id, corrected = payload.decode(bits, key)
    mag = np.abs(soft)
    noise = float(np.std(soft - np.sign(soft) * mag.mean())) or 1e-9
    confidence = float(mag.mean() / noise)
    weak = int((mag < 0.25 * mag.mean()).sum())
    return Extraction(wm_id, corrected, round(confidence, 2), weak)


def extract(img: Image.Image, key: bytes) -> Extraction:
    """Blind extraction: assumes the image is the full page (any resolution)."""
    return extract_array(to_canonical(img), key)
