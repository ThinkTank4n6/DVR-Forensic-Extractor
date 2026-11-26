"""mediacarve as the length judge for standard video containers.

Adapted from Forensic Media Extractor's fme/engines/carve_judge.py (same
author, MIT). A signature with ``"judge": "mediacarve"`` (MP4/MOV, AVI,
MKV/WebM) asks mediacarve where the file ends. mediacarve walks the format's
own structure and says how it got the length:

    header    the file's own header recorded the length
    parsed    the length came from walking the structure to its end
    capped    the end was not confirmed: the length is a ceiling, not a fact

Rules (the same as FME's):
1. mediacarve confirms the length (header/parsed): use it.
   ...unless another valid video header starts inside that length: the file
   was overwritten, so it is cut there and labelled capped.
2. It can't confirm the end, but the header is real (mediacarve capped it, or
   DFX's own mode accepted it): keep the partial file, cut at the next video
   header mediacarve validates, labelled capped. A capped item hides nothing.
3. Neither accepts it: not a file.

mediacarve knows nothing of DVR formats (DHAV, IMKH); those keep DFX's own modes.
"""
from __future__ import annotations

import os
from typing import Optional

from .. import vendored

# Bytes read to find the header at a candidate's own offset (longer than any
# mediacarve signature).
_WINDOW = 64


class _Stream:
    """A DFX Source seen as the read-only seekable stream mediacarve reads."""

    def __init__(self, src):
        self._src, self._size, self._pos = src, src.size, 0

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            self._pos = offset
        elif whence == os.SEEK_CUR:
            self._pos += offset
        else:
            self._pos = self._size + offset
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, size: int = -1) -> bytes:
        if self._pos >= self._size or self._pos < 0:
            return b""
        if size is None or size < 0:
            size = self._size - self._pos
        data = self._src.read_full(self._pos, size)
        self._pos += len(data)
        return data


def version() -> str:
    return vendored.mediacarve().__version__


def _caps(mc, max_size: int) -> dict:
    return {kind: min(cap, max_size) for kind, cap in mc.DEFAULT_CAPS.items()}


def measure(src, start: int, max_size: int):
    """mediacarve's reading of a header at exactly `start`, or None."""
    mc = vendored.mediacarve()
    end = min(start + _WINDOW, src.size)
    if end <= start:
        return None
    for hit in mc.carve(_Stream(src), kinds=mc.MEDIA_KINDS, caps=_caps(mc, max_size),
                        start=start, end=end, nested=True):
        if hit.offset == start:
            return hit
        if hit.offset > start:
            break
    return None


def next_video_header(src, lo: int, hi: int, max_size: int) -> Optional[int]:
    """First offset in [lo, hi) where mediacarve validates a *video* header.

    Video only: a partial MP4 often holds JPEG thumbnails, and cutting at one
    would throw away the rest of the partial video.
    """
    if hi <= lo:
        return None
    mc = vendored.mediacarve()
    for hit in mc.carve(_Stream(src), kinds=mc.VIDEO_KINDS, caps=_caps(mc, max_size),
                        start=lo, end=hi, nested=True):
        return hit.offset
    return None


def judge(src, start: int, own_end: Optional[int], own_note: str, max_size: int):
    """(end, note, bounded) or (None, reason, "") when neither accepts the header."""
    hit = measure(src, start, max_size)
    if hit is not None and hit.bounded in ("header", "parsed"):
        # A confirmed length is what the file *declared*. On a DVR drive the old file's
        # tail is often overwritten by a newer recording; its header still declares the
        # full length. A valid video header inside that range means exactly that, and
        # the newer file must not be hidden.
        inner = next_video_header(src, start + 1, hit.end, max_size)
        if inner is not None:
            return (inner, f"end estimated: mediacarve {hit.kind}{hit.ext} declared {hit.length:,} bytes "
                           f"({hit.bounded}), but another video starts inside it at 0x{inner:X} - "
                           "probably overwritten; cut there", "capped")
        return hit.end, f"mediacarve {hit.kind}{hit.ext}: length {hit.bounded}", hit.bounded
    if hit is None and own_end is None:
        return None, "rejected by mediacarve and by the signature's own mode", ""
    ceiling = hit.end if hit is not None else own_end
    nxt = next_video_header(src, start + 1, ceiling, max_size)
    end = nxt if nxt is not None else ceiling
    why = ("mediacarve capped the length" if hit is not None
           else "mediacarve did not recognize the header; signature's own mode accepted it")
    cut = f"; cut at the next video header (0x{nxt:X})" if nxt is not None else ""
    return end, f"end estimated: {why}{cut} ({own_note or 'no note'})", "capped"
