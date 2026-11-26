"""Signature carving engine.

Scans a read-only Source in large overlapping chunks, finds every enabled
signature's header, works out where each item ends using the signature's
mode, and copies the item out with MD5/SHA-256 hashes and a CSV log.

Long scans write a checkpoint so they can resume after a crash or reboot.
"""
from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from ..source import Source
from .signatures import hex_literal, hex_to_regex, normalize, clean_for_record, parse_hex

MB = 1024 * 1024

ISO_TOP_BOXES = {
    b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta",
    b"moof", b"mfra", b"styp", b"sidx", b"ssix", b"prft", b"pdin", b"udta",
    b"pnot", b"PICT", b"junk", b"emsg", b"jP  ", b"mvhd",
}


# ----------------------------------------------------------------- timestamps
def decode_timestamp(raw: int, fmt: str) -> str | None:
    """Return ISO-8601 text as recorded by the device (no time zone applied)."""
    try:
        if fmt == "unix":
            return _dt.datetime.fromtimestamp(raw, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        if fmt == "filetime":
            return (_dt.datetime(1601, 1, 1) + _dt.timedelta(microseconds=raw // 10)).strftime("%Y-%m-%d %H:%M:%S")
        if fmt == "dahua_packed":
            sec = raw & 0x3F
            mi = (raw >> 6) & 0x3F
            hr = (raw >> 12) & 0x1F
            day = (raw >> 17) & 0x1F
            mon = (raw >> 22) & 0x0F
            yr = (raw >> 26) + 2000
            return _dt.datetime(yr, mon, day, hr, mi, sec).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError, OSError):
        return None
    return None


def _read_uint(buf: bytes, off: int, size: int, endian: str) -> int | None:
    if off < 0 or off + size > len(buf):
        return None
    return int.from_bytes(buf[off:off + size], endian)


# -------------------------------------------------------------------- results
@dataclass
class CarvedItem:
    item_no: int
    signature_id: str
    signature_name: str
    start: int
    end: int
    length: int
    status: str = "carved"          # carved | logged (dry run) | incomplete
    notes: str = ""
    file: str = ""
    md5: str = ""
    sha256: str = ""
    frames: int = 0
    channels: str = ""
    first_time: str = ""
    last_time: str = ""

    CSV_FIELDS = ("item_no", "signature_id", "signature_name", "start", "start_hex",
                  "end", "length", "status", "notes", "file", "md5", "sha256",
                  "frames", "channels", "first_time", "last_time")

    def row(self) -> dict:
        d = asdict(self)
        d["start_hex"] = f"0x{self.start:X}"
        return d


@dataclass
class CarveOptions:
    out_dir: str
    start: int = 0
    end: int | None = None
    chunk_size: int = 64 * MB
    dry_run: bool = False
    force_sector_aligned: bool = False
    max_items: int = 0                 # 0 = unlimited
    checkpoint_every: float = 15.0     # seconds
    resume: bool = False


@dataclass
class CarveStats:
    scanned: int = 0
    total: int = 0
    items: int = 0
    rejected: int = 0
    bytes_carved: int = 0
    started: str = ""
    finished: str = ""
    elapsed: float = 0.0
    canceled: bool = False
    per_signature: dict = field(default_factory=dict)


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# --------------------------------------------------------------------- engine
class Carver:
    def __init__(self, source: Source, signatures: list[dict], options: CarveOptions,
                 progress=None, cancel=None, log=None):
        self.src = source
        self.opt = options
        self.progress = progress or (lambda stats: None)
        self.cancel = cancel or (lambda: False)
        self.log = log or (lambda msg: None)
        self.sigs = []
        for raw in signatures:
            s = normalize(raw)
            s["_re"] = re.compile(hex_to_regex(s["header"]), re.DOTALL)
            s["_hlen"] = len(parse_hex(s["header"]))
            s["_footer"] = hex_literal(s.get("footer", ""))
            s["_align"] = int(s["align"]) or source.sector_size
            self.sigs.append(s)
        self.overlap = max([s["_hlen"] + int(s["header_offset"]) for s in self.sigs] + [16])
        self.out = Path(options.out_dir)
        self.stats = CarveStats(total=0)
        self.items: list[CarvedItem] = []
        self._last_end: dict[str, int] = {}

    # ------------------------------------------------------------- paths
    @property
    def csv_path(self) -> Path:
        return self.out / "carve_log.csv"

    @property
    def ckpt_path(self) -> Path:
        return self.out / "checkpoint.json"

    @property
    def session_path(self) -> Path:
        return self.out / "carve_session.json"

    # ------------------------------------------------------------- end finders
    def _end_header_footer(self, s, start):
        foot = s["_footer"]
        limit = min(start + int(s["max_size"]), self.src.size)
        pos = start + s["_hlen"] + int(s["header_offset"])
        window = 8 * MB
        found = None
        while pos < limit:
            buf = self.src.read_at(pos, min(window + len(foot) - 1, limit - pos))
            if not buf:
                break
            if s["footer_search"] == "first":
                i = buf.find(foot)
                if i >= 0:
                    found = pos + i
                    break
            else:
                i = buf.rfind(foot)
                if i >= 0:
                    found = pos + i
            pos += window
        if found is not None:
            end = min(found + len(foot) + int(s["footer_tail"]), self.src.size)
            return end, ""
        if s["on_missing_footer"] == "maxsize":
            return limit, "footer not found; took max_size"
        return None, "footer not found within max_size"

    def _length_from_field(self, s, start):
        lf = s["length_field"]
        off, size = int(lf["offset"]), int(lf["size"])
        buf = self.src.read_at(start + off, size)
        v = _read_uint(buf, 0, size, lf.get("endian", "little"))
        if v is None:
            return None
        return v * int(lf.get("multiplier", 1) or 1) + int(lf.get("adjust", 0))

    def _end_header_length(self, s, start):
        n = self._length_from_field(s, start)
        if n is None:
            return None, "length field unreadable"
        if n < int(s["min_size"]) or n > int(s["max_size"]):
            return None, f"length {n} outside min/max"
        if start + n > self.src.size:
            return self.src.size, f"truncated: length {n} runs past end of source"
        return start + n, ""

    def _end_maxsize(self, s, start):
        end = min(start + int(s["max_size"]), self.src.size)
        return end, "" if end - start == int(s["max_size"]) else "truncated at end of source"

    def _end_box_walk(self, s, start):
        pos = start
        limit = min(start + int(s["max_size"]), self.src.size)
        seen = []
        while pos + 8 <= limit:
            h = self.src.read_at(pos, 16)
            if len(h) < 8:
                break
            size = int.from_bytes(h[:4], "big")
            btype = h[4:8]
            if btype not in ISO_TOP_BOXES:
                break
            if size == 1:
                if len(h) < 16:
                    break
                size = int.from_bytes(h[8:16], "big")
                if size < 16:
                    break
            elif size == 0:          # box runs to end of file - unknown on raw media
                break
            elif size < 8:
                break
            if not seen and btype != b"ftyp":
                return None, "first box is not ftyp"
            if pos + size > limit:
                seen.append(btype.decode("latin-1"))
                return limit, "last box runs past max_size/end of source (truncated)"
            seen.append(btype.decode("latin-1"))
            pos += size
        if not seen:
            return None, "no valid boxes"
        note = "boxes: " + ",".join(seen)
        if "moov" not in seen:
            note += "; no moov box (incomplete - may not play)"
        if "mdat" not in seen and "moof" not in seen:
            note += "; no media data box"
        return pos, note

    def _walk_chain(self, s, start):
        lf = s["length_field"]
        hdr_re = s["_re"]
        hoff = int(s["header_offset"])
        limit = min(start + int(s["max_size"]), self.src.size)
        foot, tail = s["_footer"], int(s["footer_tail"])
        cf, tf = s.get("channel_field"), s.get("timestamp_field")
        need = max(int(lf["offset"]) + int(lf["size"]),
                   (int(cf["offset"]) + int(cf["size"])) if cf else 0,
                   (int(tf["offset"]) + int(tf["size"])) if tf else 0,
                   hoff + s["_hlen"])
        cur = start
        frames = 0
        channels = set()
        first_t = last_t = ""
        bad_footer = 0
        while cur < limit:
            h = self.src.read_at(cur, need)
            if len(h) < need or not hdr_re.match(h, hoff):
                # gap tolerance: look ahead for the next header
                gap = int(s["chain_max_gap"])
                if gap and frames:
                    look = self.src.read_at(cur, gap + s["_hlen"] + hoff)
                    m = hdr_re.search(look, hoff)
                    if m and m.start() - hoff <= gap:
                        cur += m.start() - hoff
                        continue
                break
            n = _read_uint(h, int(lf["offset"]), int(lf["size"]), lf.get("endian", "little"))
            n = n * int(lf.get("multiplier", 1) or 1) + int(lf.get("adjust", 0))
            if n < max(need, 1) or cur + n > self.src.size or n > int(s["max_size"]):
                break
            if foot:
                fpos = cur + n - tail - len(foot)
                if self.src.read_at(fpos, len(foot)) != foot:
                    bad_footer += 1
                    break
            if cf:
                v = _read_uint(h, int(cf["offset"]), int(cf["size"]), "little")
                if v is not None:
                    channels.add(v)
            if tf:
                v = _read_uint(h, int(tf["offset"]), int(tf["size"]), tf.get("endian", "little"))
                t = decode_timestamp(v, tf["format"]) if v is not None else None
                if t:
                    first_t = first_t or t
                    last_t = t
            frames += 1
            cur += n
        if frames == 0:
            return None, "no valid frame at header", {}
        meta = {"frames": frames,
                "channels": ",".join(str(c) for c in sorted(channels)),
                "first_time": first_t, "last_time": last_t}
        note = f"{frames} frames"
        if cur >= limit and limit < self.src.size:
            note += "; stopped at max_size"
        return cur, note, meta

    # ------------------------------------------------------------- extraction
    def _write_item(self, s, item: CarvedItem):
        sub = self.out / "carved" / s["id"]
        sub.mkdir(parents=True, exist_ok=True)
        name = f"{item.item_no:06d}_off{item.start:012X}.{s['extension']}"
        path = sub / name
        md5, sha = hashlib.md5(), hashlib.sha256()
        pos, end = item.start, item.end
        with open(path, "wb") as f:
            while pos < end:
                b = self.src.read_at(pos, min(16 * MB, end - pos))
                if not b:
                    break
                f.write(b)
                md5.update(b)
                sha.update(b)
                pos += len(b)
        item.file = str(path.relative_to(self.out))
        item.md5, item.sha256 = md5.hexdigest(), sha.hexdigest()

    def _process_hit(self, s, start) -> bool:
        if start < 0 or start >= self.src.size:
            return False
        if start < self._last_end.get(s["id"], -1):
            return False  # inside an item already carved with this signature
        if (s["sector_aligned"] or self.opt.force_sector_aligned) and start % s["_align"]:
            return False
        meta = {}
        mode = s["mode"]
        if mode == "header_footer":
            end, note = self._end_header_footer(s, start)
        elif mode == "header_length":
            end, note = self._end_header_length(s, start)
        elif mode == "header_maxsize":
            end, note = self._end_maxsize(s, start)
        elif mode == "box_walk":
            end, note = self._end_box_walk(s, start)
        elif mode == "frame_chain":
            end, note, meta = self._walk_chain(s, start)
        else:
            end, note = None, f"unknown mode {mode}"
        if end is None or end - start < int(s["min_size"]):
            self.stats.rejected += 1
            return False
        item = CarvedItem(item_no=len(self.items) + 1, signature_id=s["id"],
                          signature_name=s["name"], start=start, end=end,
                          length=end - start, notes=note, **meta)
        if "incomplete" in note or "truncated" in note:
            item.status = "incomplete"
        if self.opt.dry_run:
            item.status = "logged" if item.status == "carved" else item.status
        else:
            self._write_item(s, item)
        self.items.append(item)
        self._append_csv(item)
        self._last_end[s["id"]] = end
        self.stats.items += 1
        self.stats.bytes_carved += item.length
        ps = self.stats.per_signature.setdefault(s["id"], 0)
        self.stats.per_signature[s["id"]] = ps + 1
        return True

    # ------------------------------------------------------------- log/ckpt
    def _append_csv(self, item: CarvedItem):
        new = not self.csv_path.exists()
        with open(self.csv_path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CarvedItem.CSV_FIELDS)
            if new:
                w.writeheader()
            w.writerow(item.row())

    def _sig_fingerprint(self) -> str:
        blob = json.dumps([clean_for_record({k: v for k, v in s.items() if not k.startswith("_")})
                           for s in self.sigs], sort_keys=True).encode()
        return hashlib.sha256(blob).hexdigest()

    def _write_checkpoint(self, next_offset: int):
        data = {"source": self.src.path, "source_size": self.src.size,
                "signatures_sha256": self._sig_fingerprint(),
                "next_offset": next_offset, "items": self.stats.items,
                "last_end": self._last_end, "written": _utc_now(),
                "dry_run": self.opt.dry_run}
        tmp = self.ckpt_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.ckpt_path)

    def _load_checkpoint(self) -> int:
        if not self.ckpt_path.exists():
            return self.opt.start
        d = json.loads(self.ckpt_path.read_text(encoding="utf-8"))
        if d.get("source_size") != self.src.size:
            raise ValueError("checkpoint belongs to a different source (size differs)")
        if d.get("signatures_sha256") != self._sig_fingerprint():
            raise ValueError("signatures changed since the checkpoint; start a new scan")
        self._last_end = {k: int(v) for k, v in d.get("last_end", {}).items()}
        if self.csv_path.exists():
            with open(self.csv_path, newline="", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    self.items.append(CarvedItem(
                        item_no=int(r["item_no"]), signature_id=r["signature_id"],
                        signature_name=r["signature_name"], start=int(r["start"]),
                        end=int(r["end"]), length=int(r["length"]), status=r["status"],
                        notes=r["notes"], file=r["file"], md5=r["md5"], sha256=r["sha256"],
                        frames=int(r["frames"] or 0), channels=r["channels"],
                        first_time=r["first_time"], last_time=r["last_time"]))
        self.stats.items = len(self.items)
        self.log(f"Resuming at offset {d['next_offset']:,} with {self.stats.items} items already logged")
        return int(d["next_offset"])

    # ------------------------------------------------------------------ run
    def run(self) -> CarveStats:
        self.out.mkdir(parents=True, exist_ok=True)
        end = min(self.opt.end or self.src.size, self.src.size)
        if self.opt.resume:
            pos = self._load_checkpoint()
        else:
            if self.csv_path.exists() or self.ckpt_path.exists():
                raise FileExistsError(f"{self.out} already holds a carve; choose a new output "
                                      "folder or resume")
            pos = self.opt.start
        self.stats.total = end - self.opt.start
        self.stats.started = _utc_now()
        self.log(f"Scan {self.src.path} from {pos:,} to {end:,} with "
                 f"{len(self.sigs)} signature(s){' (dry run)' if self.opt.dry_run else ''}")
        t0 = time.time()
        last_ck = t0
        chunk = max(int(self.opt.chunk_size), 4096)
        while pos < end:
            if self.cancel():
                self.stats.canceled = True
                self.log("Canceled by user; checkpoint saved - you can resume")
                break
            data = self.src.read_at(pos, min(chunk + self.overlap, end - pos + self.overlap))
            if not data:
                break
            body = min(chunk, end - pos)
            hits = []
            for s in self.sigs:
                hoff = int(s["header_offset"])
                for m in s["_re"].finditer(data):
                    if m.start() >= body:
                        break
                    hits.append((pos + m.start() - hoff, s))
            hits.sort(key=lambda h: h[0])
            for start, s in hits:
                if self.opt.max_items and self.stats.items >= self.opt.max_items:
                    break
                self._process_hit(s, start)
            pos += body
            self.stats.scanned = pos - self.opt.start
            self.stats.elapsed = time.time() - t0
            self.progress(self.stats)
            if time.time() - last_ck >= self.opt.checkpoint_every:
                self._write_checkpoint(pos)
                last_ck = time.time()
            if self.opt.max_items and self.stats.items >= self.opt.max_items:
                self.log(f"Stopped at max_items={self.opt.max_items}")
                break
        self._write_checkpoint(pos)
        self.stats.finished = _utc_now()
        self.stats.elapsed = time.time() - t0
        self._write_session(end)
        self.log(f"Done: {self.stats.items} item(s), {self.stats.rejected} rejected hit(s), "
                 f"{self.stats.elapsed:.1f}s")
        return self.stats

    def _write_session(self, end):
        data = {
            "source": self.src.describe(),
            "range": {"start": self.opt.start, "end": end},
            "options": asdict(self.opt),
            "signatures": [clean_for_record({k: v for k, v in s.items() if not k.startswith("_")})
                           for s in self.sigs],
            "signatures_sha256": self._sig_fingerprint(),
            "stats": asdict(self.stats),
        }
        self.session_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
