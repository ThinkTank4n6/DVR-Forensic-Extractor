"""Signature learner: draft a signature from known-good sample files.

Give it 3+ samples of one format (exports from the recorder, or byte ranges
picked in the hex viewer). It looks for:

  header          bytes every sample starts with (variable bytes become ??)
  frame marker    the header repeating inside every sample -> a frame stream
  length field    a number in each frame (or file) header equal to the
                  distance to the next frame (or the file size), +- a constant
  footer          bytes every frame (or file) ends with, and any bytes after it
  timestamp       a field that decodes to plausible, non-decreasing times
  channel         a small number that is constant inside a sample but
                  differs between samples (suggestion only)

It then writes a *draft* signature (validated: false), and self-tests it by
planting every sample in random data and carving it back: each sample must be
found at its offset with its exact length.

Everything it reports says how much evidence backs it. A learned signature is
a starting point for an examiner, never a validated signature.
"""
from __future__ import annotations

import datetime as _dt
import os
import random
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .carve.engine import decode_timestamp

SAMPLE_CAP = 64 * 1024 * 1024     # bytes analyzed per sample (frames); size/tail always exact
HEADER_SPAN = 16                  # bytes of header considered
MIN_FRAMES = 3
MAX_FILE_HEADER = 4096            # frames may start after a file header this long (Dahua/Hikvision exports)
FRAMES_PER_SAMPLE = 2000          # frames per sample used for field analysis (bounds the time taken)


@dataclass
class Sample:
    name: str
    size: int
    head: bytes        # first SAMPLE_CAP bytes
    tail: bytes        # last 64 bytes
    origin: str        # file path, or "evidence @ 0x... (+n)"

    @property
    def complete(self) -> bool:
        return len(self.head) == self.size


def sample_from_file(path: str) -> Sample:
    p = Path(path)
    size = p.stat().st_size
    with open(p, "rb") as f:
        head = f.read(SAMPLE_CAP)
        f.seek(max(0, size - 64))
        tail = f.read(64)
    return Sample(p.name, size, head, tail, str(p))


def sample_from_bytes(name: str, data: bytes, origin: str = "") -> Sample:
    return Sample(name, len(data), data[:SAMPLE_CAP], data[-64:], origin or name)


def _hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)


def _pattern(rows: list[bytes], span: int) -> list[int | None]:
    """Per position: the byte if all rows agree, else None."""
    n = min(span, min(len(r) for r in rows))
    out = []
    for i in range(n):
        v = rows[0][i]
        out.append(v if all(r[i] == v for r in rows) else None)
    return out


def _header_from(pattern: list[int | None]) -> list[int | None]:
    """Leading constant run, extended across a variable gap only when 4+ constant
    bytes follow it (RIFF????AVI LIST yes; DHAV?<ch>... no - that would bake in
    one camera's channel number)."""
    lead = 0
    while lead < len(pattern) and pattern[lead] is not None:
        lead += 1
    hdr = pattern[:lead]
    i = lead
    while i < len(pattern):
        j = i
        while j < len(pattern) and pattern[j] is None:
            j += 1
        k = j
        while k < len(pattern) and pattern[k] is not None:
            k += 1
        if j == i or k - j < 4:
            break
        hdr = pattern[:k]
        i = k
    return hdr


def _mask_fields(hdr: list[int | None], fields) -> list[int | None]:
    """Bytes inside a learned field (length, timestamp) vary by definition: make them ??
    even if the samples happened to agree (small files share a size's high bytes)."""
    out = list(hdr)
    for f in fields:
        if not f:
            continue
        for i in range(int(f["offset"]), int(f["offset"]) + int(f["size"])):
            if i < len(out):
                out[i] = None
    while out and out[-1] is None:
        out.pop()
    return out


def _hex_pattern(p: list[int | None]) -> str:
    return " ".join("??" if v is None else f"{v:02X}" for v in p)


def _positions(data: bytes, marker: bytes) -> list[int]:
    out, at = [], data.find(marker)
    while at >= 0:
        out.append(at)
        at = data.find(marker, at + 1)
    return out


def _find_length_field(frames: list[tuple[bytes, int]], max_off: int = 64):
    """frames: (frame_bytes_from_its_start, true_length). Returns best
    (offset, size, endian, adjust, hits, total) or None."""
    best = None
    total = len(frames)
    for size in (4, 2, 8):
        for endian in ("little", "big"):
            for off in range(0, max_off):
                adjs = {}
                for fb, ln in frames:
                    if off + size > len(fb):
                        continue
                    v = int.from_bytes(fb[off:off + size], endian)
                    if v == 0:
                        continue
                    a = ln - v
                    if -64 <= a <= 64:
                        adjs[a] = adjs.get(a, 0) + 1
                if not adjs:
                    continue
                adj, hits = max(adjs.items(), key=lambda kv: (kv[1], -abs(kv[0])))
                score = (hits, -abs(adj), -off, size == 4)
                if hits >= max(2, int(0.9 * total)) and (best is None or score > best[0]):
                    best = (score, (off, size, endian, adj, hits, total))
    return best[1] if best else None


def _find_tail_footer(ends: list[bytes]):
    """ends: last 24 bytes of each frame/file. Footer = 4 (or 2) constant bytes at
    a fixed distance from the end; bytes after it are the tail."""
    if len(ends) < 2:
        return None
    for flen in (4, 2):
        for back in range(flen, 17):           # footer starts `back` bytes before the end
            vals = {e[len(e) - back:len(e) - back + flen] for e in ends if len(e) >= back}
            if len(vals) == 1:
                v = next(iter(vals))
                if v.strip(b"\x00") and v.strip(b"\xff"):
                    return v, back - flen
    return None


def _timestamp_candidates(per_sample: list[list[bytes]], max_off: int = 40):
    """A field that decodes to plausible times that never go backwards *within*
    each sample (samples may have been recorded in any order)."""
    out = []
    lo, hi = "2005-01-01 00:00:00", "2040-01-01 00:00:00"   # ISO strings sort like times
    for fmt in ("dahua_packed", "unix"):
        for endian in ("little", "big"):
            for off in range(0, max_off - 3):
                ok, alltimes = True, []
                for frames in per_sample:
                    times = []
                    for fb in frames:
                        if off + 4 > len(fb):
                            ok = False
                            break
                        t = decode_timestamp(int.from_bytes(fb[off:off + 4], endian), fmt)
                        if not t or not lo <= t <= hi:
                            ok = False
                            break
                        times.append(t)
                    if not ok or not all(b >= a for a, b in zip(times, times[1:])):
                        ok = False
                        break
                    if times:
                        span = (_dt.datetime.strptime(times[-1], "%Y-%m-%d %H:%M:%S")
                                - _dt.datetime.strptime(times[0], "%Y-%m-%d %H:%M:%S")).total_seconds()
                        if span > 86400:
                            ok = False
                            break
                    alltimes += times
                if ok and len(alltimes) >= MIN_FRAMES:
                    out.append({"offset": off, "size": 4, "endian": endian, "format": fmt,
                                "first": min(alltimes), "last": max(alltimes)})
    # prefer formats whose values actually change (a constant field is a weaker signal)
    out.sort(key=lambda c: (c["first"] == c["last"], c["format"] != "dahua_packed", c["offset"]))
    return out


def _channel_candidates(per_sample_frames: list[list[bytes]], max_off: int = 16):
    """Byte offsets constant within each sample, < 64, and different between samples."""
    if len(per_sample_frames) < 2:
        return []
    out = []
    for off in range(4, max_off):
        vals = []
        for frames in per_sample_frames:
            vs = {f[off] for f in frames if len(f) > off}
            if len(vs) != 1:
                break
            vals.append(next(iter(vs)))
        else:
            if len(set(vals)) > 1 and max(vals) < 64:
                out.append({"offset": off, "size": 1, "values": vals})
    return out


def _analyze_frames(samples, marker, max_lead: int = 0):
    """None if `marker` isn't a frame stream; else (frame_mode|None, findings, warnings, frame_header).
    max_lead > 0 allows a file header before the first frame."""
    per_sample_pos = [_positions(s.head, marker) for s in samples]
    if not all(p and p[0] <= max_lead and len(p) >= MIN_FRAMES for p in per_sample_pos):
        return None
    findings, warnings = [], []
    leads = sorted({p[0] for p in per_sample_pos})
    if leads != [0]:
        findings.append({"what": "file header before frames",
                         "value": ", ".join(f"{x:,} bytes" for x in leads),
                         "evidence": "each sample starts with a file header, then the frames; the signature describes "
                                     "the frames (what a DVR drive holds), not the export's file header"})
    frames, ends, frame_heads, per_sample_frames = [], [], [], []
    for s, pos in zip(samples, per_sample_pos):
        bounds = pos + ([s.size] if s.complete else [])
        bounds = bounds[:FRAMES_PER_SAMPLE + 1]
        sf = []
        for a, b in zip(bounds, bounds[1:]):
            fb = s.head[a:b]
            frames.append((fb[:96], b - a))
            ends.append(fb[-24:])
            frame_heads.append(fb[:96])
            sf.append(fb[:96])
        per_sample_frames.append(sf)
    nfr = sum(len(p) for p in per_sample_pos)
    findings.append({"what": "frame marker", "value": _hex(marker),
                     "evidence": f"repeats {nfr:,} times across the samples"
                                 + (", always at sample start" if leads == [0] else ", starting after the file header")
                                 + ": a stream of frames"
                                 + (f" (fields checked on the first {FRAMES_PER_SAMPLE:,} frames of each sample)"
                                    if any(len(p) > FRAMES_PER_SAMPLE for p in per_sample_pos) else "")})
    fhdr = _header_from(_pattern(frame_heads, HEADER_SPAN))
    findings.append({"what": "frame header", "value": _hex_pattern(fhdr),
                     "evidence": f"first bytes of all {len(frame_heads):,} frames"})
    lf = _find_length_field(frames)
    if not lf:
        warnings.append(f"The marker {_hex(marker)} repeats, but no length field explains the frame sizes.")
        return None, findings, warnings, None
    off, size, endian, adj, hits, total = lf
    fm = {"length_field": {"offset": off, "size": size, "endian": endian, "adjust": adj, "multiplier": 1}}
    findings.append({"what": "frame length field",
                     "value": f"offset {off}, {size} bytes, {endian}-endian, adjust {adj:+d}",
                     "evidence": f"equals the distance to the next frame in {hits:,} of {total:,} frames"})
    ft = _find_tail_footer(ends)
    if ft:
        fm["footer"], fm["footer_tail"] = _hex(ft[0]), ft[1]
        findings.append({"what": "frame footer", "value": f"{_hex(ft[0])} + {ft[1]} byte(s) after it",
                         "evidence": f"at the same distance from the end of all {len(ends):,} frames"})
    ts = _timestamp_candidates(per_sample_frames)
    if ts:
        t = ts[0]
        fm["timestamp_field"] = {"offset": t["offset"], "size": 4, "endian": t["endian"], "format": t["format"]}
        findings.append({"what": "timestamp field (candidate)",
                         "value": f"offset {t['offset']}, {t['format']}, {t['endian']}-endian",
                         "evidence": f"decodes to times between {t['first']} and {t['last']}, never going "
                                     f"backwards inside a sample ({len(ts)} candidate(s); check against the recording time)"})
    ch = _channel_candidates(per_sample_frames)
    if ch:
        c = ch[0]
        fm["channel_field"] = {"offset": c["offset"], "size": 1}
        findings.append({"what": "channel field (suggestion)", "value": f"offset {c['offset']}",
                         "evidence": f"constant inside each sample, values {c['values']} across samples - "
                                     "confirm with samples from known channels"})
    elif len(samples) >= 2:
        warnings.append("No channel field found. Use samples from different known channels to find it.")
    return fm, findings, warnings, fhdr


def _offset_marker_candidates(samples, limit: int = 12):
    """4-byte markers that repeat in every sample, first seen within MAX_FILE_HEADER bytes."""
    from collections import Counter
    win = samples[0].head[:256 * 1024]
    counts = Counter(win[i:i + 4] for i in range(0, max(0, len(win) - 3)))
    first = {}
    for i in range(0, min(MAX_FILE_HEADER, len(win) - 3)):
        first.setdefault(win[i:i + 4], i)
    cands = [g for g, i in first.items()
             if counts[g] >= MIN_FRAMES and len(set(g)) > 1 and i > 0
             and all(s.head.find(g, 0, MAX_FILE_HEADER + 4) >= 0 for s in samples[1:])]
    cands.sort(key=lambda g: (-counts[g], first[g]))
    return cands[:limit]


def recognize_standard(samples) -> dict | None:
    """If every sample is a standard container mediacarve fully understands, say so:
    the built-in signature already recovers it and no learned signature is needed."""
    import io
    from . import vendored
    builtin = {"mp4": "mp4-iso", "avi": "avi-riff", "mkv": "mkv-ebml"}
    try:
        mc = vendored.mediacarve()
    except RuntimeError:
        return None
    kinds = set()
    for s in samples:
        if not s.complete:
            return None
        hit = next(iter(mc.carve(io.BytesIO(s.head), kinds=mc.VIDEO_KINDS, start=0, end=64, nested=True)), None)
        if hit is None or hit.offset != 0 or hit.bounded not in ("header", "parsed"):
            return None
        kinds.add(hit.kind)
    if len(kinds) != 1:
        return None
    k = kinds.pop()
    return {"kind": k, "builtin": builtin.get(k)}


def _recognize_asf(samples) -> dict | None:
    from .carve import asf
    for s in samples:
        if not s.complete:
            return None
        res = asf.walk(lambda o, n, b=s.head: b[o:o + n], 0, s.size)
        if not res or res["end"] != s.size:
            return None
    return {"kind": "asf", "builtin": "asf-wmv"}


def learn(samples: list[Sample], sig_id: str = "", name: str = "") -> dict:
    findings, warnings = [], []
    if not samples:
        raise ValueError("add at least one sample")
    if len(samples) < 3:
        warnings.append(f"Only {len(samples)} sample(s). With fewer than 3, DFX can't tell fixed bytes "
                        "from bytes that just happen to match. Add more samples from the same recorder.")
    for s in samples:
        if not s.complete:
            warnings.append(f"{s.name}: only the first {SAMPLE_CAP // (1024 * 1024)} MB was analyzed for frames.")
    ext = Path(samples[0].name).suffix.lstrip(".").lower()
    ext = ext if ext.isalnum() and 0 < len(ext) <= 10 else "bin"

    # 1. file header
    pat = _pattern([s.head for s in samples], HEADER_SPAN)
    hdr = _header_from(pat)
    lead = b""
    for v in hdr:
        if v is None:
            break
        lead += bytes([v])
    recognized = recognize_standard(samples) or _recognize_asf(samples)
    if recognized:
        warnings.insert(0, f"These are standard {recognized['kind'].upper()} files: DFX's built-in signature "
                           f"'{recognized['builtin']}' already recovers them, with exact lengths from mediacarve. "
                           "You don't need a learned signature for them.")
    findings.append({"what": "header", "value": _hex_pattern(hdr),
                     "evidence": f"first bytes of all {len(samples)} samples"
                                 + (f"; ?? = bytes that differ between samples" if None in hdr else "")})

    # 2. frame structure: does a leading marker repeat inside every sample?
    #    Try the shortest plausible marker first: a longer one can include a
    #    frame-type byte (DHAV FD = keyframe only) and miss most frames.
    frame_mode, fallback = None, None
    tries = [(lead[:mlen], 0) for mlen in range(4, min(8, len(lead)) + 1)]
    if not recognized:
        tries += [(g, MAX_FILE_HEADER) for g in _offset_marker_candidates(samples)]
    for marker, max_lead in tries:
        res = _analyze_frames(samples, marker, max_lead)
        if res is None:
            continue
        if res[0] is not None:                   # a length field explains the frames
            fallback = None
            fm, fnd, wrn, fhdr = res
            lead = marker
            findings[:] = [f for f in findings if f["what"] != "header"]   # frame header replaces it
            findings.extend(fnd)
            warnings.extend(wrn)
            frame_mode, hdr = fm, fhdr
            break
        fallback = fallback or res
    if fallback:
        findings.extend(fallback[1])
        warnings.extend(fallback[2])
    if len(lead) < 2 and not frame_mode:
        raise ValueError("the samples don't share common first bytes or a repeating frame marker; they may not "
                         "be the same format, or the selections don't start at the file/frame start")

    if frame_mode:
        hdr = _mask_fields(hdr, [frame_mode.get("length_field"), frame_mode.get("timestamp_field")])
    sig = {"id": sig_id or ("learned-" + lead[:4].hex()), "name": name or f"Learned: {_hex(lead[:4])}",
           "extension": ext, "header": _hex_pattern(hdr), "header_offset": 0,
           "validated": False, "enabled": True,
           "notes": "Draft from the DFX signature learner: " + "; ".join(f"{f['what']} = {f['value']}" for f in findings)
                    + ". NOT VALIDATED."}
    biggest = max(s.size for s in samples)
    if frame_mode:
        sig.update(mode="frame_chain", chain_max_gap=0, min_size=32,
                   max_size=min(max(biggest * 4, 1 << 20), 1 << 32), **frame_mode)
    else:
        # 3. whole-file length field
        lf = None
        if all(s.complete or len(s.head) >= 96 for s in samples):
            lf = _find_length_field([(s.head[:160], s.size) for s in samples], max_off=128)
            if lf and len(samples) < 2 and lf[3] not in (0, 8):
                lf = None
        # 4. file footer
        ft = _find_tail_footer([s.tail[-24:] for s in samples])
        if lf and lf[4] == len(samples):
            off, size, endian, adj, hits, total = lf
            hdr = _mask_fields(hdr, [{"offset": off, "size": size}])
            sig["header"] = _hex_pattern(hdr)
            sig.update(mode="header_length", length_field={"offset": off, "size": size, "endian": endian,
                                                           "adjust": adj, "multiplier": 1},
                       min_size=max(16, min(s.size for s in samples) // 4), max_size=min(biggest * 4, 1 << 34))
            findings.append({"what": "file length field", "value": f"offset {off}, {size} bytes, {endian}-endian, adjust {adj:+d}",
                             "evidence": f"equals the file size in all {total} samples"})
        elif ft:
            sig.update(mode="header_footer", footer=_hex(ft[0]), footer_tail=ft[1], footer_search="first",
                       on_missing_footer="skip", min_size=max(16, min(s.size for s in samples) // 4),
                       max_size=min(biggest * 4, 1 << 34))
            findings.append({"what": "file footer", "value": f"{_hex(ft[0])} + {ft[1]} byte(s) after it",
                             "evidence": f"every sample ends with it"})
            warnings.append("header_footer stops at the FIRST footer: if the footer bytes can also occur inside "
                            "the file, items will be cut short. Check the self-test and real data.")
        else:
            sig.update(mode="header_maxsize", min_size=16, max_size=min(biggest * 2, 1 << 34))
            warnings.append("No length field or footer found: the draft takes up to max_size bytes "
                            "(ending early at the next header). Lengths will be estimates (capped).")
    for f in findings:                      # report the header actually used, after field masking
        if f["what"] in ("header", "frame header"):
            f["value"] = sig["header"]
    if len(_hex_pattern(hdr).replace("??", "").split()) < 4:
        warnings.append("The header has fewer than 4 fixed bytes; expect false hits in unallocated space.")
    # where each item really starts inside its sample: after any file header
    skip = [s.head.find(lead) if frame_mode else 0 for s in samples]
    test = self_test(sig, samples, skip=skip)
    if test.get("estimated"):
        if test["passed"]:
            warnings.append("Self-test: every sample was found at its start. In this mode the end can only be "
                            "estimated, so lengths are not expected to match exactly.")
        else:
            warnings.append("Self-test failed: not every sample was found at its start. See the self-test table.")
    elif not test["passed"]:
        warnings.append("Self-test failed: the draft does not recover every sample exactly. See the self-test table.")
    return {"signature": sig, "findings": findings, "warnings": warnings, "self_test": test,
            "recognized": recognized,
            "samples": [{"name": s.name, "size": s.size, "origin": s.origin} for s in samples]}


def self_test(sig: dict, samples: list[Sample], seed: int = 7, skip: list[int] | None = None) -> dict:
    """Plant every (complete) sample in random data, carve with `sig`, compare.
    skip[i] = bytes of file header before the item the signature describes."""
    from .carve import Carver, CarveOptions
    from .source import open_source
    rnd = random.Random(seed)
    skip = skip or [0] * len(samples)
    usable = [(s, k) for s, k in zip(samples, skip) if s.complete]
    if not usable:
        return {"passed": False, "results": [], "note": "no sample small enough to plant (all over the analysis cap)"}
    blob, planted = bytearray(rnd.randbytes(4096 + 13)), []
    for s, k in usable:
        planted.append((s.name, len(blob) + k, s.size - k))
        blob += s.head
        blob += rnd.randbytes(4096 + rnd.randrange(4096))
    with tempfile.TemporaryDirectory() as td:
        img = Path(td) / "selftest.img"
        img.write_bytes(bytes(blob))
        with open_source(str(img)) as src:
            c = Carver(src, [sig], CarveOptions(out_dir=str(Path(td) / "o"), dry_run=True))
            c.run()
    got = {i.start: i for i in c.items}
    estimated = sig.get("mode") == "header_maxsize"
    results = []
    for nm, at, ln in planted:
        it = got.get(at)
        ok = it is not None and (estimated or it.length == ln)
        results.append({"sample": nm, "offset": at, "length": ln, "found": it is not None,
                        "carved_length": it.length if it else 0, "ok": ok})
    extra = [i.start for i in c.items if i.start not in {p[1] for p in planted}]
    return {"passed": all(r["ok"] for r in results) and not extra, "results": results,
            "extra_hits": len(extra), "estimated": estimated}
