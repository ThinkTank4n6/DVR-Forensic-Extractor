"""ASF (Windows Media) structure walk - Dahua NVRs and players export .asf.

An ASF file is a sequence of top-level objects, each a 16-byte GUID followed by
a 64-bit little-endian size that includes the 24-byte object header:

    Header object   (contains sub-objects, including File Properties)
    Data object     (the packets)
    Index objects   (optional: Simple Index, Index, Media Object Index, Timecode Index)

The file's length is the sum of the top-level objects. The File Properties
object inside the header also records the file size, a creation date (FILETIME)
and the play duration, which DFX reports.

Checked against ffmpeg-written ASF: Header 634 + Data 44,850 + Simple Index 98
= 45,582 bytes = the File Properties file size.
"""
from __future__ import annotations

import datetime as _dt
import struct
import uuid

HEADER = bytes.fromhex("3026B2758E66CF11A6D900AA0062CE6C")
TOP_LEVEL = {
    HEADER: "header",
    bytes.fromhex("3626B2758E66CF11A6D900AA0062CE6C"): "data",
    bytes.fromhex("90080033B1E5CF1189F400A0C90349CB"): "simple_index",
    uuid.UUID("D6E229D3-35DA-11D1-9034-00A0C90349BE").bytes_le: "index",
    uuid.UUID("FEB103F8-12AD-4C64-840F-2A1D2F7AD48C").bytes_le: "media_object_index",
    uuid.UUID("3CB73FD0-0C4A-4803-953D-EDF7B6228F0C").bytes_le: "timecode_index",
}
FILE_PROPERTIES = uuid.UUID("8CABDCA1-A947-11CF-8EE4-00C00C205365").bytes_le
MAX_HEADER_OBJECT = 16 * 1024 * 1024


def _filetime(v: int) -> str:
    if v <= 0:
        return ""
    try:
        d = _dt.datetime(1601, 1, 1) + _dt.timedelta(microseconds=v // 10)
    except OverflowError:
        return ""
    return d.strftime("%Y-%m-%d %H:%M:%S UTC") if d.year >= 1990 else ""


def file_properties(header_obj: bytes) -> dict:
    """Parse the File Properties sub-object out of a complete Header object."""
    if len(header_obj) < 30:
        return {}
    count = struct.unpack_from("<I", header_obj, 24)[0]
    pos = 30
    for _ in range(min(count, 512)):
        if pos + 24 > len(header_obj):
            break
        g = header_obj[pos:pos + 16]
        size = struct.unpack_from("<Q", header_obj, pos + 16)[0]
        if size < 24:
            break
        if g == FILE_PROPERTIES and pos + 88 <= len(header_obj):
            fsize, cdate, _pkts, play, _send, preroll = struct.unpack_from("<QQQQQQ", header_obj, pos + 40)
            dur = max(0.0, play / 1e7 - preroll / 1000.0)
            return {"file_size": fsize, "created": _filetime(cdate), "duration_s": round(dur, 3)}
        pos += size
    return {}


def walk(read_at, start: int, limit: int) -> dict | None:
    """Walk top-level ASF objects from `start`. read_at(offset, n) -> bytes.
    Returns {end, objects, truncated, properties} or None if this isn't ASF."""
    pos, objs, props, truncated = start, [], {}, False
    while pos + 24 <= limit:
        h = read_at(pos, 24)
        if len(h) < 24:
            break
        name = TOP_LEVEL.get(h[:16])
        size = struct.unpack_from("<Q", h, 16)[0]
        if name is None or size < 24:
            break
        if name == "header" and objs:
            break                     # an ASF file has one header object: a second one is the next file
        if not objs:
            if name != "header" or size > MAX_HEADER_OBJECT or size < 30:
                return None
            props = file_properties(read_at(pos, size))
        if pos + size > limit:
            objs.append(name)
            truncated = True
            pos = limit
            break
        objs.append(name)
        pos += size
    if not objs or "data" not in objs:
        return None
    return {"end": pos, "objects": objs, "truncated": truncated, "properties": props}


def describe(res: dict, start: int) -> str:
    p = res["properties"]
    parts = ["objects: " + ",".join(res["objects"])]
    length = res["end"] - start
    if p.get("file_size"):
        parts.append("header file size " + ("matches" if p["file_size"] == length else
                                            f"{p['file_size']:,} (walk found {length:,})"))
    if p.get("created"):
        parts.append(f"created {p['created']}")
    if p.get("duration_s"):
        parts.append(f"duration {p['duration_s']:g} s")
    if res["truncated"]:
        parts.append("truncated: last object runs past max_size/end of source")
    return "; ".join(parts)
