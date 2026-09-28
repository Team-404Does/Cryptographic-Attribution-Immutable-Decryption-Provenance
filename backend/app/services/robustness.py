"""Adversarial robustness harness: simulated leak transformations vs. extraction success."""
from __future__ import annotations

import io
import time

import cv2
import numpy as np
import pymupdf
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter

from ..watermark import pdf_wm, text_wm
from . import references, sessions


def _jpeg(img: Image.Image, q: int) -> Image.Image:
    b = io.BytesIO()
    img.convert("RGB").save(b, "JPEG", quality=q)
    return Image.open(io.BytesIO(b.getvalue()))


def _noise(img: Image.Image, sigma: float, seed: int = 7) -> Image.Image:
    a = np.asarray(img.convert("RGB"), dtype=np.float32)
    a += np.random.default_rng(seed).normal(0, sigma, a.shape)
    return Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))


def _scale(img: Image.Image, f: float) -> Image.Image:
    return img.resize((int(img.width * f), int(img.height * f)), Image.BICUBIC)


def _print_scan(img: Image.Image) -> Image.Image:
    """Crude print->scan model: resample, toner blur, contrast/brightness drift, sensor noise, JPEG."""
    x = _scale(img, 200 / 150)
    x = x.filter(ImageFilter.GaussianBlur(1.1))
    x = ImageEnhance.Contrast(x).enhance(1.15)
    x = ImageEnhance.Brightness(x).enhance(0.97)
    x = _noise(x, 5)
    return _jpeg(x, 80)


def _screenshot(img: Image.Image, dpi: int) -> Image.Image:
    # the viewer re-renders the page at screen resolution, then the OS captures it as PNG
    return _scale(img, dpi / pdf_wm.RENDER_DPI)


def _crop(img: Image.Image, x0: float, y0: float, x1: float, y1: float) -> Image.Image:
    w, h = img.size
    return img.crop((int(w * x0), int(h * y0), int(w * x1), int(h * y1)))


def _viewer_screenshot(img: Image.Image) -> Image.Image:
    """Page shown in a PDF viewer: grey canvas, toolbar, page at ~64 % zoom, captured as JPEG."""
    page = _scale(img.convert("RGB"), 0.64)
    canvas = Image.new("RGB", (page.width + 420, page.height + 170), (82, 86, 89))
    d = ImageDraw.Draw(canvas)
    d.rectangle([0, 0, canvas.width, 50], fill=(50, 54, 57))
    d.text((24, 17), "PM-2026-17.pdf     1 / 2     -  100%  +", fill=(225, 225, 225))
    canvas.paste(page, (210, 95))
    return _jpeg(canvas, 85)


def _phone_photo(img: Image.Image) -> Image.Image:
    """Hand-held photo: perspective tilt, dark surround, resampling, lens blur, sensor noise, JPEG."""
    a = np.asarray(img.convert("RGB"))
    h, w = a.shape[:2]
    src = np.float32([[0, 0], [w, 0], [w, h], [0, h]])
    dst = np.float32([[w * .06, h * .03], [w * .98, 0], [w, h], [w * .012, h * .988]])
    warped = cv2.warpPerspective(a, cv2.getPerspectiveTransform(src, dst), (w, h), borderValue=(40, 40, 40))
    x = _scale(Image.fromarray(warped), 0.7).filter(ImageFilter.GaussianBlur(0.8))
    return _jpeg(_noise(x, 5), 75)


TRANSFORMS = [
    ("Original recipient copy", lambda i: i),
    ("Screenshot @ 96 dpi (PNG)", lambda i: _screenshot(i, 96)),
    ("Screenshot @ 72 dpi (PNG)", lambda i: _screenshot(i, 72)),
    ("Screenshot @ 96 dpi + JPEG q75", lambda i: _jpeg(_screenshot(i, 96), 75)),
    ("JPEG recompression q90", lambda i: _jpeg(i, 90)),
    ("JPEG recompression q50", lambda i: _jpeg(i, 50)),
    ("JPEG recompression q25", lambda i: _jpeg(i, 25)),
    ("Downscale 50%", lambda i: _scale(i, 0.5)),
    ("Upscale 150%", lambda i: _scale(i, 1.5)),
    ("Gaussian blur r=1.5", lambda i: i.filter(ImageFilter.GaussianBlur(1.5))),
    ("Gaussian noise sigma=10", lambda i: _noise(i, 10)),
    ("Greyscale conversion", lambda i: i.convert("L")),
    ("Contrast +40% / brightness -10%",
     lambda i: ImageEnhance.Brightness(ImageEnhance.Contrast(i).enhance(1.4)).enhance(0.9)),
    ("Denoise (median 3x3)", lambda i: i.filter(ImageFilter.MedianFilter(3))),
    ("Print-scan simulation", _print_scan),
    ("Photo of screen (blur+noise+JPEG q60)",
     lambda i: _jpeg(_noise(_scale(i, 0.8).filter(ImageFilter.GaussianBlur(1.2)), 8), 60)),
    ("Screenshot inside PDF viewer (chrome + grey canvas)", _viewer_screenshot),
    ("Crop: centre 50 % of the page", lambda i: _crop(i, .25, .25, .75, .75)),
    ("Crop: top 40 % of the page", lambda i: _crop(i, 0, 0, 1, .4)),
    ("Crop: margins trimmed", lambda i: _crop(i, .05, .05, .95, .95)),
    ("Rotate 3°", lambda i: i.rotate(3, expand=True, fillcolor=(255, 255, 255))),
    ("Rotate 8° + crop", lambda i: _crop(i.rotate(8, fillcolor=(70, 70, 70)), .08, .06, .9, .8)),
    ("Phone photo (perspective + blur + noise + JPEG)", _phone_photo),
    ("Tiny crop (18 % of page) downscaled 60 % + JPEG q70",
     lambda i: _jpeg(_scale(_crop(i, .16, .17, .65, .57), 0.6), 70)),
]


def simulate_leak(session_id: str, transform: int, page: int = 0) -> bytes:
    """Render a leaked artefact (JPEG) of the recipient copy after one transformation."""
    if not 0 <= transform < len(TRANSFORMS):
        raise ValueError("unknown transform")
    doc = pymupdf.open(stream=sessions.copy_path(session_id).read_bytes(), filetype="pdf")
    img = TRANSFORMS[transform][1](pdf_wm._page_image(doc[min(page, doc.page_count - 1)]))
    doc.close()
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "JPEG", quality=92)
    return buf.getvalue()


def run(session_id: str) -> dict:
    ses = sessions.get(session_id)
    if not ses:
        raise sessions.SessionError("unknown session")
    copy = sessions.copy_path(session_id).read_bytes()
    expected = ses["wm_id"]
    key = sessions.watermark_key()
    doc = pymupdf.open(stream=copy, filetype="pdf")
    page_img = pdf_wm._page_image(doc[0])
    refs = [r for r in references.pages(ses["doc_id"]) if r.page_no == 0]
    text = "".join(p.get_text() for p in doc)
    doc.close()

    results = []
    for name, fn in TRANSFORMS:
        t0 = time.perf_counter()
        r = pdf_wm.extract_image(fn(page_img), key, name, refs_fn=lambda: refs)
        results.append({"channel": "raster", "transform": name, "recovered": r.wm_id,
                        "success": r.wm_id == expected, "confidence": r.detail["confidence"],
                        "alignment": r.detail["alignment"] if r.wm_id else "—",
                        "rs_corrected_bytes": r.detail["rs_corrected_bytes"],
                        "ms": round((time.perf_counter() - t0) * 1000)})

    text_cases = [
        ("Copy/paste full text", text),
        ("Copy/paste one paragraph", text[len(text) // 4: len(text) // 4 + 700]),
        ("Copy/paste short sentence (under capacity)", text[200:320]),
        ("Retyped / homoglyphs normalised", text_wm.strip(text)),
    ]
    for name, t in text_cases:
        wm, frames, _ = text_wm.extract(t, key)
        results.append({"channel": "text", "transform": name, "recovered": wm.hex() if wm else None,
                        "success": bool(wm and wm.hex() == expected), "confidence": frames,
                        "rs_corrected_bytes": None, "ms": 0})
    ok = sum(r["success"] for r in results)
    return {"session_id": session_id, "expected_watermark": expected, "passed": ok, "total": len(results),
            "results": results}
