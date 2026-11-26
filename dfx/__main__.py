"""Command line.

  dfx gui      [--port 8788] [--no-browser]
  dfx carve    SOURCE OUT_DIR [--sig ID ...] [--all] [--dry-run] [--aligned]
               [--start N] [--end N] [--chunk-mb 64] [--max-items N] [--resume]
  dfx hash     SOURCE
  dfx sigs     [--check FILE.json]
  dfx drives
  dfx doctor
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys

from . import APP_NAME, __version__, DEFAULT_PORT


def _int(v: str) -> int:
    v = v.replace(",", "").strip()
    return int(v, 16) if v.lower().startswith("0x") else int(v)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dfx", description=f"{APP_NAME} {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    g = sub.add_parser("gui")
    g.add_argument("--port", type=int, default=DEFAULT_PORT)
    g.add_argument("--no-browser", action="store_true")
    c = sub.add_parser("carve")
    c.add_argument("source")
    c.add_argument("out_dir")
    c.add_argument("--sig", action="append", default=[], help="signature id (repeatable)")
    c.add_argument("--all", action="store_true", help="every valid signature, including disabled ones")
    c.add_argument("--dry-run", action="store_true")
    c.add_argument("--aligned", action="store_true")
    c.add_argument("--start", type=_int, default=0)
    c.add_argument("--end", type=_int, default=0)
    c.add_argument("--chunk-mb", type=int, default=64)
    c.add_argument("--max-items", type=int, default=0)
    c.add_argument("--resume", action="store_true")
    h = sub.add_parser("hash")
    h.add_argument("source")
    s = sub.add_parser("sigs")
    s.add_argument("--check", metavar="FILE")
    sub.add_parser("drives")
    sub.add_parser("doctor")
    a = ap.parse_args(argv)

    if a.cmd in (None, "gui"):
        from .server import serve
        return serve(port=getattr(a, "port", DEFAULT_PORT), open_browser=not getattr(a, "no_browser", False)) or 0

    from .server import config_dir
    from .carve import SignatureLibrary, Carver, CarveOptions, check
    from .source import open_source, hash_source, list_physical_drives

    lib = SignatureLibrary(config_dir() / "signatures")

    if a.cmd == "sigs":
        if a.check:
            data = json.load(open(a.check, encoding="utf-8"))
            for sig in (data if isinstance(data, list) else [data]):
                errs = check(sig)
                print(f"{sig.get('id', '?'):20} {'OK' if not errs else '; '.join(errs)}")
            return 0
        for sig in lib.all():
            flag = "validated" if sig.get("validated") else "NOT validated"
            on = "on " if sig.get("enabled") else "off"
            prob = f"  PROBLEMS: {'; '.join(sig['problems'])}" if sig.get("problems") else ""
            print(f"[{on}] {sig['id']:16} {sig['mode']:15} {flag:13} {sig['name']}{prob}")
        return 0

    if a.cmd == "drives":
        for d in list_physical_drives():
            print(f"{d['path']:22} {d['size']:>18,} bytes  sector {d['sector_size']}")
        return 0

    if a.cmd == "hash":
        with open_source(a.source) as src:
            r = hash_source(src, progress=lambda d, t: print(f"\r{100 * d / t:5.1f}%", end="", file=sys.stderr))
        print(file=sys.stderr)
        print(f"MD5     {r['md5']}\nSHA-256 {r['sha256']}\nBytes   {r['bytes']:,}")
        return 0

    if a.cmd == "doctor":
        import platform
        print(f"{APP_NAME} {__version__}")
        print(f"Python  {platform.python_version()} ({platform.system()} {platform.release()})")
        ok = sys.version_info >= (3, 11)
        print(f"  Python 3.11+ ............ {'OK' if ok else 'TOO OLD'}")
        from . import vendored
        vend = vendored.verify()
        for v in vend:
            print(f"  {v['name']:<12} {v['version']:<8} {'OK (byte-identical)' if v['ok'] else 'CHANGED - SHA-256 does not match vendored.json'}")
        try:
            vendored.ewfprobe(), vendored.mediacarve()
            print("  E01 / length judge ...... loaded")
        except RuntimeError as e:
            print(f"  E01 / length judge ...... FAILED: {e}")
            vend.append({"ok": False})
        print(f"  ffmpeg (for later builds)  {'found' if shutil.which('ffmpeg') else 'not found'}")
        sigs = lib.all()
        bad = [x for x in sigs if x.get('problems')]
        print(f"  Signatures .............. {len(sigs)} loaded, {len(bad)} with problems")
        print(f"  Config folder ........... {config_dir()}")
        return 0 if ok and not bad and all(v["ok"] for v in vend) else 1

    if a.cmd == "carve":
        sigs = [x for x in lib.all() if not x.get("problems")]
        if a.sig:
            sigs = [x for x in sigs if x["id"] in a.sig]
            missing = set(a.sig) - {x["id"] for x in sigs}
            if missing:
                print(f"unknown or invalid signature(s): {', '.join(sorted(missing))}", file=sys.stderr)
                return 2
        elif not a.all:
            sigs = [x for x in sigs if x.get("enabled")]
        opt = CarveOptions(out_dir=a.out_dir, start=a.start, end=a.end or None,
                           chunk_size=a.chunk_mb * 1024 * 1024, dry_run=a.dry_run,
                           force_sector_aligned=a.aligned, max_items=a.max_items, resume=a.resume)

        def prog(st):
            pct = 100 * st.scanned / st.total if st.total else 100
            print(f"\r{pct:5.1f}%  items {st.items}", end="", file=sys.stderr)

        with open_source(a.source) as src:
            st = Carver(src, sigs, opt, progress=prog, log=lambda m: print(f"\n{m}", file=sys.stderr)).run()
        from .report import build_report
        rep = build_report(a.out_dir)
        print(f"\n{st.items} item(s). Report: {rep}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
