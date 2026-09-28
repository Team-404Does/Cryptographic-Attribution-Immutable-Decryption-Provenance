"""PDF watermarking: raster channel burned into the page + homoglyph text layer.

Each output page is the original page rendered at RENDER_DPI with the
spread-spectrum watermark burned in, overlaid by an invisible (render mode 3)
text layer that keeps the copy searchable/copyable and carries the
homoglyph channel. Removing the text layer does not remove the raster mark,
and copy/pasting the text keeps the homoglyph mark (only retyping strips it).
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field

import pymupdf
from PIL import Image

from . import image_wm, text_wm

RENDER_DPI = 150
_FONT = pymupdf.Font("notos")  # Noto Sans: covers Latin, Cyrillic and Greek homoglyphs


def _render(page: pymupdf.Page, dpi: int = RENDER_DPI) -> Image.Image:
    pix = page.get_pixmap(dpi=dpi, alpha=False)
    return Image.frombytes("RGB", (pix.width, pix.height), pix.samples)


class PdfTooLarge(ValueError):
    pass


def check_render_size(doc: pymupdf.Document, max_pages: int, max_pixels: int, dpi: int = RENDER_DPI) -> None:
    """Reject documents whose rendering would exhaust memory (huge page sizes or counts)."""
    if doc.page_count > max_pages:
        raise PdfTooLarge(f"PDF has {doc.page_count} pages; the limit is {max_pages}")
    scale = (dpi / 72) ** 2
    for i, page in enumerate(doc):
        if page.rect.width * page.rect.height * scale > max_pixels:
            raise PdfTooLarge(f"page {i + 1} is too large to render ({page.rect.width:.0f}x{page.rect.height:.0f} pt)")


def watermark_pdf(pdf: bytes, wm_id: bytes, key: bytes) -> bytes:
    src = pymupdf.open(stream=pdf, filetype="pdf")
    out = pymupdf.open()
    text_pos = 0
    for page in src:
        marked = image_wm.embed(_render(page), wm_id, key)
        buf = io.BytesIO()
        marked.save(buf, "PNG", optimize=True)
        np_ = out.new_page(width=page.rect.width, height=page.rect.height)
        np_.insert_image(np_.rect, stream=buf.getvalue())
        np_.insert_font(fontname="wmF", fontbuffer=_FONT.buffer)
        for block in page.get_text("dict")["blocks"]:
            for line in block.get("lines", []):
                for span in line["spans"]:
                    if not span["text"].strip():
                        continue
                    txt, text_pos = text_wm.embed(span["text"], wm_id, key, text_pos)
                    np_.insert_text(span["origin"], txt, fontname="wmF",
                                    fontsize=span["size"], render_mode=3)
    out.set_metadata({"producer": "Offline Document Viewer", "creator": "", "title": src.metadata.get("title", "")})
    data = out.tobytes(garbage=4, deflate=True)
    src.close()
    out.close()
    return data


@dataclass
class ChannelResult:
    channel: str
    location: str
    wm_id: str | None
    detail: dict = field(default_factory=dict)


def _page_image(page: pymupdf.Page) -> Image.Image:
    """Prefer the embedded full-page raster (lossless) over a re-render."""
    imgs = page.get_images(full=True)
    if len(imgs) == 1:
        info = page.parent.extract_image(imgs[0][0])
        if info and info.get("image"):
            return Image.open(io.BytesIO(info["image"]))
    return _render(page)


def extract_image(img: Image.Image, key: bytes, location: str = "image", refs_fn=None) -> ChannelResult:
    """Blind extraction first; if it fails and reference pages are available, register the evidence
    onto its source page (handles crops, rotation, perspective, viewer chrome) and decode again."""
    e = image_wm.extract(img, key)
    result = ChannelResult("raster-spread-spectrum", location, e.wm_id.hex() if e.wm_id else None,
                           {"confidence": e.confidence, "rs_corrected_bytes": e.corrected_bytes,
                            "weak_bits": e.bit_errors_hint, "alignment": "full-page"})
    if e.wm_id or refs_fn is None:
        return result
    reg = register_and_extract(img, key, refs_fn())
    return reg or result


def register_and_extract(img: Image.Image, key: bytes, refs, tries: int = 3) -> ChannelResult | None:
    from . import registration
    if not refs:
        return None
    leak = registration.prepare_leak(img)
    ranked = sorted(refs, key=lambda r: len(registration.good_matches(leak, r)[0]), reverse=True)
    for ref in ranked[:tries]:
        reg = registration.register(leak, ref)
        if not reg:
            continue
        e = image_wm.extract_array(reg.warped, key, reg.valid)
        if e.wm_id:
            return ChannelResult("raster-registered", f"image → {ref.doc_id} page {ref.page_no + 1}", e.wm_id.hex(),
                                 {"confidence": e.confidence, "rs_corrected_bytes": e.corrected_bytes,
                                  "inliers": reg.inliers, "page_coverage": round(reg.coverage, 2),
                                  "alignment": "homography"})
    return None


def extract_text(text: str, key: bytes, location: str = "text") -> ChannelResult:
    wm_id, frames, phase = text_wm.extract(text, key)
    return ChannelResult("homoglyph-text", location, wm_id.hex() if wm_id else None,
                         {"eligible_chars": text_wm.capacity(text), "frames": frames, "phase": phase})


def extract_pdf(pdf: bytes, key: bytes, max_pages: int = 100, max_pixels: int = 60_000_000,
                refs_fn=None) -> list[ChannelResult]:
    doc = pymupdf.open(stream=pdf, filetype="pdf")
    try:
        check_render_size(doc, max_pages, max_pixels)
    except PdfTooLarge:
        doc.close()
        raise
    results, all_text = [], []
    for i, page in enumerate(doc):
        results.append(extract_image(_page_image(page), key, f"page {i + 1}", refs_fn))
        all_text.append(page.get_text())
    results.append(extract_text("".join(all_text), key, "pdf text layer"))
    doc.close()
    return results
