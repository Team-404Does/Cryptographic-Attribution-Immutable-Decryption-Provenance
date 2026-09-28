"""Informed geometric registration of leaked images onto their source page.

Blind extraction assumes the evidence is the full page. Real leaks are often
cropped, rotated, rescaled, photographed at an angle or surrounded by viewer
chrome. The examiner holds the original documents, so each candidate page is
rendered once, ORB features are matched against the evidence, a RANSAC
homography maps the evidence back onto the page's canonical grid, and the
watermark is decoded from just the covered cells.
"""
from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np
from PIL import Image

from . import image_wm

REF_FEATURES = 6000
LEAK_FEATURES = 8000
MAX_LEAK_SIDE = 2600      # feature detection works on a downscaled copy of huge photos
RATIO = 0.78              # Lowe ratio test
MIN_INLIERS = 20


@dataclass
class PageRef:
    doc_id: str
    page_no: int
    gray: np.ndarray       # canonical grid, uint8 (CANON_W wide)
    kp: np.ndarray         # (N, 2) float32 keypoint coordinates
    des: np.ndarray        # ORB descriptors


def _orb(n: int):
    return cv2.ORB_create(nfeatures=n, scaleFactor=1.2, nlevels=10, edgeThreshold=15, patchSize=31, fastThreshold=8)


def _features(gray: np.ndarray, n: int) -> tuple[np.ndarray, np.ndarray | None]:
    kps, des = _orb(n).detectAndCompute(gray, None)
    return np.float32([k.pt for k in kps]).reshape(-1, 2), des


def make_ref(doc_id: str, page_no: int, page_img: Image.Image) -> PageRef:
    gray = image_wm.to_canonical(page_img).astype(np.uint8)
    kp, des = _features(gray, REF_FEATURES)
    return PageRef(doc_id, page_no, gray, kp, des)


@dataclass
class Leak:
    gray: np.ndarray       # full-resolution greyscale evidence (uint8)
    kp: np.ndarray         # keypoints in full-resolution coordinates
    des: np.ndarray | None


def prepare_leak(img: Image.Image) -> Leak:
    gray = np.asarray(img.convert("L"), dtype=np.uint8)
    scale = min(1.0, MAX_LEAK_SIDE / max(gray.shape))
    small = gray if scale == 1.0 else cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
    kp, des = _features(small, LEAK_FEATURES)
    return Leak(gray, kp / scale, des)


def good_matches(leak: Leak, ref: PageRef) -> tuple[np.ndarray, np.ndarray]:
    if leak.des is None or ref.des is None or len(leak.des) < 2 or len(ref.des) < 2:
        return np.empty((0, 2), np.float32), np.empty((0, 2), np.float32)
    pairs = cv2.BFMatcher(cv2.NORM_HAMMING).knnMatch(leak.des, ref.des, k=2)
    good = [p[0] for p in pairs if len(p) == 2 and p[0].distance < RATIO * p[1].distance]
    src = np.float32([leak.kp[m.queryIdx] for m in good]).reshape(-1, 2)
    dst = np.float32([ref.kp[m.trainIdx] for m in good]).reshape(-1, 2)
    return src, dst


@dataclass
class Registration:
    warped: np.ndarray     # evidence resampled onto the page's canonical grid (float32)
    valid: np.ndarray      # (cells_y, cells_x) bool - cells fully covered by the evidence
    inliers: int
    coverage: float        # fraction of the page covered by the evidence
    homography: np.ndarray


def register(leak: Leak, ref: PageRef) -> Registration | None:
    src, dst = good_matches(leak, ref)
    if len(src) < MIN_INLIERS:
        return None
    H, inl = cv2.findHomography(src, dst, cv2.RANSAC, 3.0, maxIters=5000, confidence=0.999)
    if H is None or int(inl.sum()) < MIN_INLIERS:
        return None
    # refine on inliers only (least squares) for sub-pixel alignment of the chip grid
    m = inl.ravel().astype(bool)
    H2, _ = cv2.findHomography(src[m], dst[m], 0)
    H = H2 if H2 is not None else H
    h, w = ref.gray.shape
    warped = cv2.warpPerspective(leak.gray, H, (w, h), flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_REPLICATE)
    cover = cv2.warpPerspective(np.full(leak.gray.shape, 255, np.uint8), H, (w, h), flags=cv2.INTER_NEAREST,
                                borderValue=0)
    cover = cv2.erode(cover, np.ones((9, 9), np.uint8))       # drop the resampled border
    cell = image_wm.CELL
    cy, cx = h // cell, w // cell
    valid = cover[: cy * cell, : cx * cell].reshape(cy, cell, cx, cell).min(axis=(1, 3)) > 0
    return Registration(warped.astype(np.float32), valid, int(inl.sum()), float(valid.mean()), H)
