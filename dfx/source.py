"""Read-only evidence sources.

Every source is opened read-only. Supported:
  * raw / dd / img / bin files
  * split raw images (.001, .002, ...)
  * Windows physical drives  (\\\\.\\PhysicalDriveN)  - needs Administrator;
    reads are sector-aligned because Windows refuses unaligned raw reads
  * E01 / Ex01 when the optional `libewf-python` (pyewf) package is installed

Nothing in this module can write to evidence.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path


class SourceError(Exception):
    pass


class Source:
    """Common interface: size, read_at(offset, length), close()."""

    path: str
    size: int
    kind: str
    sector_size: int = 512

    def read_at(self, offset: int, length: int) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def describe(self) -> dict:
        return {"path": self.path, "kind": self.kind, "size": self.size,
                "sector_size": self.sector_size}


# --------------------------------------------------------------------------- raw
class RawSource(Source):
    kind = "raw"

    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "rb")  # read-only
        self._f.seek(0, os.SEEK_END)
        self.size = self._f.tell()

    def read_at(self, offset: int, length: int) -> bytes:
        if offset >= self.size or length <= 0:
            return b""
        self._f.seek(offset)
        return self._f.read(min(length, self.size - offset))

    def close(self):
        self._f.close()


class SplitRawSource(Source):
    """image.001, image.002, ... read as one continuous image."""
    kind = "split-raw"

    def __init__(self, first: str):
        p = Path(first)
        stem = p.name[: -len(p.suffix)]
        width = len(p.suffix) - 1
        parts = []
        n = int(p.suffix[1:])
        while True:
            cand = p.with_name(f"{stem}.{n:0{width}d}")
            if not cand.exists():
                break
            parts.append(cand)
            n += 1
        if not parts:
            raise SourceError(f"no segments found for {first}")
        self.path = first
        self.parts = [(open(x, "rb"), x.stat().st_size) for x in parts]
        self.size = sum(s for _, s in self.parts)

    def read_at(self, offset: int, length: int) -> bytes:
        out = bytearray()
        base = 0
        end = min(offset + length, self.size)
        for f, sz in self.parts:
            if offset < base + sz and end > base:
                s = max(offset, base) - base
                e = min(end, base + sz) - base
                f.seek(s)
                out += f.read(e - s)
            base += sz
            if base >= end:
                break
        return bytes(out)

    def close(self):
        for f, _ in self.parts:
            f.close()


# ------------------------------------------------------------- Windows physical
class PhysicalDriveSource(Source):
    """Windows physical drive opened read-only with aligned reads."""
    kind = "physical"

    def __init__(self, path: str):
        if not sys.platform.startswith("win"):
            raise SourceError("physical drive access is only implemented for Windows")
        import ctypes
        from ctypes import wintypes

        self.path = path
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ, FILE_SHARE_WRITE = 1, 2
        OPEN_EXISTING = 3
        k32.CreateFileW.restype = wintypes.HANDLE
        h = k32.CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            None, OPEN_EXISTING, 0, None)
        if h in (None, wintypes.HANDLE(-1).value):
            err = ctypes.get_last_error()
            raise SourceError(f"cannot open {path} (Windows error {err}). "
                              "Run DFX as Administrator.")
        self._k32, self._h = k32, h

        # IOCTL_DISK_GET_LENGTH_INFO
        length = ctypes.c_longlong(0)
        ret = wintypes.DWORD(0)
        ok = k32.DeviceIoControl(h, 0x7405C, None, 0, ctypes.byref(length),
                                 ctypes.sizeof(length), ctypes.byref(ret), None)
        if not ok:
            raise SourceError(f"cannot read size of {path}")
        self.size = length.value

        # IOCTL_DISK_GET_DRIVE_GEOMETRY -> BytesPerSector at offset 20
        geo = (ctypes.c_byte * 24)()
        if k32.DeviceIoControl(h, 0x70000, None, 0, geo, 24, ctypes.byref(ret), None):
            self.sector_size = int.from_bytes(bytes(geo)[20:24], "little") or 512
        # Python file object on top of the handle for simple seek/read
        import msvcrt
        fd = msvcrt.open_osfhandle(h, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        self._f = os.fdopen(fd, "rb", buffering=0)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        ss = self.sector_size
        a_start = offset - (offset % ss)
        a_end = -(-(offset + length) // ss) * ss
        a_end = min(a_end, self.size)
        self._f.seek(a_start)
        buf = self._f.read(a_end - a_start)
        s = offset - a_start
        return buf[s:s + length]

    def close(self):
        try:
            self._f.close()
        except Exception:
            pass


def list_physical_drives() -> list[dict]:
    """Windows: physical drives that can be opened (needs Administrator)."""
    out = []
    if not sys.platform.startswith("win"):
        return out
    for i in range(32):
        p = rf"\\.\PhysicalDrive{i}"
        try:
            s = PhysicalDriveSource(p)
            out.append({"path": p, "size": s.size, "sector_size": s.sector_size})
            s.close()
        except SourceError:
            continue
    return out


# ------------------------------------------------------------------------ E01
class EwfSource(Source):
    kind = "e01"

    def __init__(self, path: str):
        try:
            import pyewf  # type: ignore
        except ImportError as e:
            raise SourceError("E01 support needs the optional package libewf-python "
                              "(pip install libewf-python)") from e
        self.path = path
        files = pyewf.glob(path)
        self._h = pyewf.handle()
        self._h.open(files)
        self.size = self._h.get_media_size()
        try:
            self.sector_size = self._h.get_bytes_per_sector()
        except Exception:
            pass

    def read_at(self, offset: int, length: int) -> bytes:
        if offset >= self.size or length <= 0:
            return b""
        return self._h.read_buffer_at_offset(min(length, self.size - offset), offset)

    def close(self):
        self._h.close()


# --------------------------------------------------------------------- factory
def open_source(path: str) -> Source:
    if re.match(r"^\\\\\.\\PhysicalDrive\d+$", path, re.I):
        return PhysicalDriveSource(path)
    p = Path(path)
    if not p.exists():
        raise SourceError(f"not found: {path}")
    if p.is_dir():
        raise SourceError(f"{path} is a folder; choose an image file or drive")
    suf = p.suffix.lower()
    if suf in (".e01", ".ex01"):
        return EwfSource(path)
    if re.fullmatch(r"\.\d{3}", suf):
        return SplitRawSource(path)
    return RawSource(path)


def hash_source(src: Source, chunk: int = 32 * 1024 * 1024, progress=None,
                cancel=None) -> dict:
    """MD5 + SHA-256 of the whole source."""
    md5, sha = hashlib.md5(), hashlib.sha256()
    off = 0
    while off < src.size:
        if cancel and cancel():
            raise InterruptedError("hashing canceled")
        b = src.read_at(off, chunk)
        if not b:
            break
        md5.update(b)
        sha.update(b)
        off += len(b)
        if progress:
            progress(off, src.size)
    return {"md5": md5.hexdigest(), "sha256": sha.hexdigest(), "bytes": off}
