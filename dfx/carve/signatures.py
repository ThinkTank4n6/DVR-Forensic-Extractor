"""Signature format, loading, saving and checking.

A signature is a JSON object. Fields:

  id               short unique id (letters, digits, - _)
  name             display name
  extension        file extension for carved items (no dot)
  enabled          include in scans by default
  header           hex bytes; "??" = any byte          e.g. "52 49 46 46 ?? ?? ?? ?? 41 56 49 20"
  header_offset    where the header sits inside the item (MP4 'ftyp' is at 4)
  mode             header_footer | header_length | header_maxsize | frame_chain | box_walk
  footer           hex bytes (header_footer, optional check in frame_chain)
  footer_tail      bytes kept after the footer (e.g. a trailing length field)
  footer_search    first | last   (header_footer: nearest or furthest footer within max_size)
  on_missing_footer skip | maxsize
  length_field     {offset, size, endian: little|big, adjust, multiplier}
                   item length = value * multiplier + adjust  (from item start)
  min_size, max_size   bytes
  sector_aligned   only accept items starting on a sector boundary
  align            boundary in bytes when sector_aligned (default: source sector size)
  chain_max_gap    frame_chain: bytes allowed between frames (0 = back-to-back)
  channel_field    {offset, size}                    recorded per frame (frame_chain)
  timestamp_field  {offset, size, endian, format}    format: unix | dahua_packed | filetime
  judge            "mediacarve" = let the vendored mediacarve decide where a standard
                   container (MP4/MOV, AVI, MKV/WebM) ends; the mode is the fallback
  validated        set true only after the signature passed your validation tests
  validation       written by DFX's Validate: {date, dfx_version, examiner, report,
                   report_sha256, definition_sha256}; cleared if the definition changes
  notes            free text (where it came from, what it was tested against)

`box_walk` is a structural mode for ISO media (MP4/MOV/3GP): the item length
comes from walking its top-level boxes. `asf_walk` does the same for ASF/WMV
(Dahua exports .asf): header + data + index objects.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

MODES = ("header_footer", "header_length", "header_maxsize", "frame_chain", "box_walk", "asf_walk")
TS_FORMATS = ("unix", "dahua_packed", "filetime")

BUILTIN_DIR = Path(__file__).resolve().parent / "signatures"

DEFAULTS = {
    "enabled": True,
    "header_offset": 0,
    "footer": "",
    "footer_tail": 0,
    "footer_search": "first",
    "on_missing_footer": "skip",
    "length_field": None,
    "min_size": 16,
    "max_size": 2 * 1024 ** 3,
    "sector_aligned": False,
    "align": 0,
    "chain_max_gap": 0,
    "channel_field": None,
    "timestamp_field": None,
    "validated": False,
    "notes": "",
    "extension": "bin",
    "judge": "",
    "validation": None,
}


class SignatureError(ValueError):
    pass


_HEX_TOKEN = re.compile(r"^(?:[0-9a-fA-F]{2}|\?\?)$")


def parse_hex(text: str) -> list[int | None]:
    """'52 49 ?? 46' -> [0x52, 0x49, None, 0x46].  Spaces optional."""
    t = (text or "").replace(",", " ").strip()
    if not t:
        return []
    if " " not in t:  # allow "524946??"
        if len(t) % 2:
            raise SignatureError(f"odd number of hex digits: {text!r}")
        tokens = [t[i:i + 2] for i in range(0, len(t), 2)]
    else:
        tokens = t.split()
    out: list[int | None] = []
    for tok in tokens:
        if not _HEX_TOKEN.match(tok):
            raise SignatureError(f"bad hex token {tok!r} in {text!r}")
        out.append(None if tok == "??" else int(tok, 16))
    return out


def hex_to_regex(text: str) -> bytes:
    parts = []
    for b in parse_hex(text):
        parts.append(b"." if b is None else re.escape(bytes([b])))
    return b"".join(parts)


def hex_literal(text: str) -> bytes:
    """Footer bytes; wildcards are not allowed in footers."""
    vals = parse_hex(text)
    if any(v is None for v in vals):
        raise SignatureError("footer cannot contain ?? wildcards")
    return bytes(vals)  # type: ignore[arg-type]


def normalize(sig: dict) -> dict:
    s = copy.deepcopy(DEFAULTS)
    s.update(sig or {})
    return s


def check(sig: dict) -> list[str]:
    """Return a list of problems (empty = OK)."""
    s = normalize(sig)
    errs = []
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", str(s.get("id", ""))):
        errs.append("id must be 1-64 letters, digits, - or _")
    if not s.get("name"):
        errs.append("name is required")
    if s["mode"] not in MODES:
        errs.append(f"mode must be one of {', '.join(MODES)}")
    try:
        h = parse_hex(s.get("header", ""))
        if len(h) < 2:
            errs.append("header needs at least 2 bytes")
        elif all(v is None for v in h):
            errs.append("header cannot be all wildcards")
    except SignatureError as e:
        errs.append(str(e))
    try:
        foot = hex_literal(s.get("footer", ""))
    except SignatureError as e:
        errs.append(str(e))
        foot = b""
    if s["mode"] == "header_footer" and not foot:
        errs.append("header_footer mode needs a footer")
    if s["mode"] in ("header_length", "frame_chain"):
        lf = s.get("length_field")
        if not isinstance(lf, dict):
            errs.append(f"{s['mode']} mode needs a length_field")
        else:
            if int(lf.get("size", 0)) not in (1, 2, 4, 8):
                errs.append("length_field.size must be 1, 2, 4 or 8")
            if lf.get("endian", "little") not in ("little", "big"):
                errs.append("length_field.endian must be little or big")
            if int(lf.get("offset", -1)) < 0:
                errs.append("length_field.offset must be >= 0")
    for k in ("min_size", "max_size", "header_offset", "footer_tail", "chain_max_gap", "align"):
        try:
            if int(s[k]) < 0:
                errs.append(f"{k} cannot be negative")
        except (TypeError, ValueError):
            errs.append(f"{k} must be a whole number")
    if not errs and int(s["min_size"]) > int(s["max_size"]):
        errs.append("min_size is larger than max_size")
    if s["footer_search"] not in ("first", "last"):
        errs.append("footer_search must be first or last")
    if s["on_missing_footer"] not in ("skip", "maxsize"):
        errs.append("on_missing_footer must be skip or maxsize")
    tf = s.get("timestamp_field")
    if tf and tf.get("format") not in TS_FORMATS:
        errs.append(f"timestamp_field.format must be one of {', '.join(TS_FORMATS)}")
    if s.get("judge") not in ("", None, "mediacarve"):
        errs.append("judge must be empty or mediacarve")
    if not re.fullmatch(r"[A-Za-z0-9]{1,10}", str(s.get("extension", ""))):
        errs.append("extension must be 1-10 letters/digits")
    return errs


class SignatureLibrary:
    """Built-in signatures (read-only, shipped) + user signatures (editable)."""

    def __init__(self, user_dir: str | Path):
        self.user_dir = Path(user_dir)
        self.user_dir.mkdir(parents=True, exist_ok=True)

    def _load_dir(self, d: Path, origin: str) -> list[dict]:
        out = []
        if not d.is_dir():
            return out
        for p in sorted(d.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                out.append({"id": p.stem, "name": p.stem, "origin": origin,
                            "load_error": str(e), "enabled": False})
                continue
            items = data if isinstance(data, list) else [data]
            for sig in items:
                s = normalize(sig)
                s["origin"] = origin
                s["problems"] = check(s)
                out.append(s)
        return out

    def all(self) -> list[dict]:
        builtin = self._load_dir(BUILTIN_DIR, "built-in")
        user = self._load_dir(self.user_dir, "user")
        # a user signature with the same id overrides the built-in one
        merged = {s["id"]: s for s in builtin}
        for s in user:
            merged[s["id"]] = s
        return sorted(merged.values(), key=lambda s: (s["origin"] != "built-in", s["name"].lower()))

    def get(self, sig_id: str) -> dict | None:
        for s in self.all():
            if s["id"] == sig_id:
                return s
        return None

    def save_user(self, sig: dict) -> dict:
        s = normalize(sig)
        for k in ("origin", "problems", "load_error"):
            s.pop(k, None)
        errs = check(s)
        if errs:
            raise SignatureError("; ".join(errs))
        path = self.user_dir / f"{s['id']}.json"
        path.write_text(json.dumps(s, indent=2), encoding="utf-8")
        return s

    def delete_user(self, sig_id: str) -> bool:
        if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", sig_id):
            return False
        p = self.user_dir / f"{sig_id}.json"
        if p.exists():
            p.unlink()
            return True
        return False


def clean_for_record(sig: dict) -> dict:
    """The exact signature definition used, for the report."""
    s = normalize(sig)
    for k in ("problems", "load_error"):
        s.pop(k, None)
    return s
