"""Loader and integrity check for the vendored third-party modules in dfx/vendor.

The modules are copied verbatim from their authors (see vendor/vendored.json).
They are imported by name from that folder, and `verify()` checks every file
against the SHA-256 recorded there - `dfx doctor` and the tests call it.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

VENDOR_DIR = Path(__file__).resolve().parent / "vendor"
if getattr(sys, "frozen", False):  # PyInstaller
    VENDOR_DIR = Path(sys._MEIPASS) / "dfx" / "vendor"  # type: ignore[attr-defined]

_cache: dict[str, object] = {}


def _load(name: str):
    if name in _cache:
        return _cache[name]
    d = str(VENDOR_DIR)
    if d not in sys.path:
        sys.path.insert(0, d)
    try:
        mod = __import__(name)
    except Exception as exc:  # noqa: BLE001 - re-raised with context
        raise RuntimeError(f"vendored module {name} (dfx/vendor/{name}.py) could not be loaded: "
                           f"{type(exc).__name__}: {exc}. This build is incomplete.") from exc
    _cache[name] = mod
    return mod


def mediacarve():
    return _load("mediacarve")


def ewfprobe():
    return _load("ewfprobe")


def manifest() -> dict:
    return json.loads((VENDOR_DIR / "vendored.json").read_text(encoding="utf-8"))


def verify() -> list[dict]:
    """[{name, version, ok, expected, actual, reason}] for every vendored file."""
    out = []
    for e in manifest()["vendored"]:
        p = VENDOR_DIR / e["path"]
        reason = ""
        if not p.exists():
            actual, reason = "missing", "file is missing"
        else:
            data = p.read_bytes()
            actual = hashlib.sha256(data).hexdigest()
            if actual != e["sha256"]:
                if b"\r\n" in data and hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest() == e["sha256"]:
                    reason = ("line endings were converted to CRLF (Git for Windows core.autocrlf); "
                              "the repository's .gitattributes must keep dfx/vendor/** -text")
                else:
                    reason = "contents differ from the vendored release"
        out.append({"name": e["name"], "version": e.get("version", ""), "ok": actual == e["sha256"],
                    "expected": e["sha256"], "actual": actual, "reason": reason})
    return out
