"""Signature validation against known data.

The examiner supplies:
  * the signature to validate
  * KNOWN FILES - originals whose exact bytes are known (for example a
    recorder's exports, hashed when received)
  * a TEST IMAGE - media the examiner prepared that holds those files
    (for example a wiped USB drive the files were copied to, some then deleted)
  * optionally a NEGATIVE IMAGE - media that holds no files of this type

DFX hashes everything, carves the test image with only that signature, and
compares. PASS requires:
  1. every known file recovered byte-for-byte (SHA-256 match),
  2. no unexpected items of this type in the test image (unless the examiner
     states the media may hold other files of this type),
  3. no items at all in the negative image, if one was given.

The result is a JSON record and an HTML report. A signature can only be marked
validated from a PASS record, and only while its definition is still exactly
the one that was tested (see `definition_sha256`).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import html
import json
import platform
import sys
from pathlib import Path

from . import APP_NAME, __version__
from .carve import Carver, CarveOptions
from .carve.signatures import clean_for_record, normalize
from .source import open_source, hash_source

PREFIX = 64 * 1024                 # bytes compared for "partial" diagnostics
_DEFINITION_IGNORES = ("validated", "notes", "validation", "enabled", "origin", "problems", "load_error")


def _utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def definition_sha256(sig: dict) -> str:
    """Hash of what makes the signature behave: everything except its labels."""
    d = clean_for_record(sig)
    for k in _DEFINITION_IGNORES:
        d.pop(k, None)
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()


def _hash_file(path: Path, cancel=None) -> dict:
    md5, sha, first = hashlib.md5(), hashlib.sha256(), hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        while True:
            if cancel and cancel():
                raise InterruptedError("validation canceled")
            b = f.read(16 * 1024 * 1024)
            if not b:
                break
            if n < PREFIX:
                first.update(b[:PREFIX - n])
            md5.update(b)
            sha.update(b)
            n += len(b)
    return {"md5": md5.hexdigest(), "sha256": sha.hexdigest(), "size": n, "prefix_sha256": first.hexdigest()}


def _prefix_sha(path: Path) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read(PREFIX)).hexdigest()


def run_validation(sig: dict, known_files: list[str], test_image: str, out_dir: str | Path,
                   negative_image: str = "", allow_other: bool = False, case: dict | None = None,
                   log=None, progress=None, cancel=None) -> dict:
    log = log or (lambda m: None)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    if not known_files:
        raise ValueError("add the known files (the originals)")
    if not test_image:
        raise ValueError("choose the test image")
    sig = normalize(sig)
    started = _utc()

    # 1. known files
    known = []
    for i, p in enumerate(known_files):
        pp = Path(p)
        if not pp.is_file():
            raise ValueError(f"known file not found: {p}")
        log(f"Validation: hashing known file {pp.name}")
        h = _hash_file(pp, cancel)
        known.append({"name": pp.name, "path": str(pp), **h})
        if progress:
            progress(stage="hashing known files", done=i + 1, total=len(known_files))
    dup = {k["sha256"] for k in known if sum(1 for x in known if x["sha256"] == k["sha256"]) > 1}
    if dup:
        raise ValueError("two known files are identical; each known file must be different")

    # 2. test image
    def carve(path: str, sub: str):
        with open_source(path) as src:
            log(f"Validation: hashing {sub} image {path}")
            ih = hash_source(src, cancel=cancel,
                             progress=lambda d, t: progress and progress(stage=f"hashing {sub} image", done=d, total=t))
            desc = src.describe()
            c = Carver(src, [sig], CarveOptions(out_dir=str(out / sub), dry_run=False),
                       cancel=cancel, log=log,
                       progress=lambda st: progress and progress(stage=f"carving {sub} image", done=st.scanned,
                                                                 total=st.total))
            st = c.run()
        if st.canceled:
            raise InterruptedError("validation canceled")
        return desc, ih, c.items, st

    t_desc, t_hash, items, t_stats = carve(test_image, "test")
    by_sha = {}
    for it in items:
        by_sha.setdefault(it.sha256, []).append(it)
    used = set()
    rows = []
    for k in known:
        hit = next((it for it in by_sha.get(k["sha256"], []) if id(it) not in used), None)
        if hit:
            used.add(id(hit))
            rows.append({**k, "status": "recovered", "offset": hit.start, "item_no": hit.item_no,
                         "bounded": hit.bounded, "note": ""})
            continue
        # diagnose: an item that starts with the same bytes but differs (truncated / overwritten / over-long)
        near = None
        for it in items:
            if id(it) in used or not it.file:
                continue
            if _prefix_sha(out / "test" / it.file) == k["prefix_sha256"]:
                near = it
                break
        if near:
            used.add(id(near))
            rows.append({**k, "status": "wrong length", "offset": near.start, "item_no": near.item_no,
                         "bounded": near.bounded,
                         "note": f"starts with the same bytes but is {near.length:,} bytes, not {k['size']:,} "
                                 f"({near.notes})"})
        else:
            rows.append({**k, "status": "not found", "offset": None, "item_no": None, "bounded": "", "note": ""})
    unexpected = [{"item_no": it.item_no, "offset": it.start, "length": it.length, "sha256": it.sha256,
                   "bounded": it.bounded, "notes": it.notes} for it in items if id(it) not in used]

    # 3. negative image
    negative = None
    if negative_image:
        n_desc, n_hash, n_items, n_stats = carve(negative_image, "negative")
        negative = {"path": negative_image, "kind": n_desc["kind"], "size": n_desc["size"],
                    "sha256": n_hash["sha256"], "md5": n_hash["md5"], "items": len(n_items),
                    "item_offsets": [it.start for it in n_items[:50]]}

    failures = []
    for r in rows:
        if r["status"] != "recovered":
            failures.append(f"{r['name']}: {r['status']}")
    if unexpected and not allow_other:
        failures.append(f"{len(unexpected)} unexpected item(s) in the test image")
    if negative and negative["items"]:
        failures.append(f"{negative['items']} item(s) found in the negative image")
    if t_stats.read_errors:
        failures.append("read problems while scanning the test image")

    from . import vendored
    record = {
        "verdict": "PASS" if not failures else "FAIL",
        "failures": failures,
        "started": started, "finished": _utc(),
        "tool": {"name": APP_NAME, "version": __version__, "python": platform.python_version(),
                 "platform": f"{platform.system()} {platform.release()}",
                 "vendored": [{k: v[k] for k in ("name", "version", "ok")} for v in vendored.verify()]},
        "case": {k: (case or {}).get(k, "") for k in ("case_number", "examiner", "agency")},
        "signature": clean_for_record(sig),
        "signature_id": sig["id"],
        "definition_sha256": definition_sha256(sig),
        "known_files": rows,
        "test_image": {"path": test_image, "kind": t_desc["kind"], "size": t_desc["size"],
                       "sha256": t_hash["sha256"], "md5": t_hash["md5"],
                       "stored_hashes": t_desc.get("stored_hashes", {})},
        "allow_other": allow_other,
        "unexpected": unexpected,
        "negative": negative,
        "read_errors": t_stats.read_errors,
    }
    (out / "validation.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    write_report(record, out / "validation_report.html")
    record["report"] = str(out / "validation_report.html")
    record["report_sha256"] = hashlib.sha256((out / "validation_report.html").read_bytes()).hexdigest()
    (out / "validation.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    log(f"Validation of '{sig['id']}': {record['verdict']}"
        + (" - " + "; ".join(failures) if failures else f" - {len(rows)} known file(s) recovered byte-for-byte"))
    return record


def _h(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _off(v) -> str:
    return "" if v is None else f"0x{v:X}"


def write_report(r: dict, path: Path) -> Path:
    ok = r["verdict"] == "PASS"
    krows = "".join(
        f"<tr><td>{_h(k['name'])}</td><td class='num'>{k['size']:,}</td><td class='mono small'>{_h(k['sha256'])}</td>"
        f"<td class='{'ok' if k['status'] == 'recovered' else 'bad'}'>{_h(k['status'])}</td>"
        f"<td class='mono'>{_off(k['offset'])}</td>"
        f"<td>{_h(k['bounded'])}</td><td class='small'>{_h(k['note'])}</td></tr>" for k in r["known_files"])
    urows = "".join(
        f"<tr><td>{u['item_no']}</td><td class='mono'>0x{u['offset']:X}</td><td class='num'>{u['length']:,}</td>"
        f"<td>{_h(u['bounded'])}</td><td class='mono small'>{_h(u['sha256'])}</td><td class='small'>{_h(u['notes'])}</td></tr>"
        for u in r["unexpected"])
    neg = r["negative"]
    neg_html = ("<p>No negative image was used.</p>" if not neg else
                f"<table class='kv'><tr><th>Image</th><td class='mono'>{_h(neg['path'])}</td></tr>"
                f"<tr><th>SHA-256</th><td class='mono'>{_h(neg['sha256'])}</td></tr>"
                f"<tr><th>Size</th><td>{neg['size']:,} bytes</td></tr>"
                f"<tr><th>Items found</th><td class='{'ok' if not neg['items'] else 'bad'}'>{neg['items']}"
                f"{' (must be 0)' if neg['items'] else ''}</td></tr></table>")
    t = r["test_image"]
    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Signature validation - {_h(r['signature_id'])}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;color:#1d232b;margin:28px;font-size:13px}}
h1{{color:#20303f;margin:0}} h2{{color:#20303f;border-bottom:2px solid #e39a2d;padding-bottom:3px;margin-top:26px}}
table{{border-collapse:collapse;width:100%;margin-top:8px}} th,td{{border:1px solid #c9d0d8;padding:4px 6px;text-align:left;vertical-align:top}}
th{{background:#eef1f4}} .kv th{{width:210px}} .mono{{font-family:Consolas,monospace}} .small{{font-size:11px}} .num{{text-align:right}}
.verdict{{font-size:22px;font-weight:700;padding:10px 14px;border-radius:6px;margin:14px 0}}
.pass{{background:#e3f3ea;color:#1f6b40;border-left:6px solid #2e7d4f}} .fail{{background:#fde8e6;color:#8e1f18;border-left:6px solid #b3261e}}
.ok{{color:#1f6b40;font-weight:600}} .bad{{color:#b3261e;font-weight:600}} .sub{{color:#5b6773}}
.warn{{background:#fff4e0;border-left:4px solid #e39a2d;padding:8px;margin:8px 0}}
pre{{background:#f6f7f9;padding:10px;font-size:11px;overflow:auto}}
</style></head><body>
<h1>Signature Validation Report</h1>
<div class="sub">{_h(r['tool']['name'])} {_h(r['tool']['version'])} &middot; Python {_h(r['tool']['python'])} &middot; {_h(r['tool']['platform'])} &middot; {_h(r['started'])} &ndash; {_h(r['finished'])}</div>
<div class="warn"><b>Early development build of DFX &mdash; not yet tested on real DVR evidence.</b></div>
<div class="verdict {'pass' if ok else 'fail'}">{'PASS' if ok else 'FAIL'} &mdash; signature <span class="mono">{_h(r['signature_id'])}</span></div>
{'' if ok else '<ul>' + ''.join(f'<li>{_h(f)}</li>' for f in r['failures']) + '</ul>'}
<h2>Method</h2>
<p>The known files were hashed. The test image was hashed and carved with only the signature under test. Each known file passes only if an item with the identical SHA-256 was recovered. Items not matching a known file are listed as unexpected{' (the examiner stated the media may contain other files of this type)' if r['allow_other'] else ' and fail the validation'}. A negative image, if given, must produce no items.</p>
<h2>Case</h2><table class="kv"><tr><th>Case number</th><td>{_h(r['case']['case_number'])}</td></tr><tr><th>Examiner</th><td>{_h(r['case']['examiner'])}</td></tr><tr><th>Agency</th><td>{_h(r['case']['agency'])}</td></tr></table>
<h2>Signature under test</h2><table class="kv"><tr><th>ID / name</th><td>{_h(r['signature_id'])} &mdash; {_h(r['signature'].get('name'))}</td></tr>
<tr><th>Mode</th><td>{_h(r['signature'].get('mode'))}</td></tr><tr><th>Definition SHA-256</th><td class="mono">{_h(r['definition_sha256'])}</td></tr></table>
<h2>Test image</h2><table class="kv"><tr><th>Path</th><td class="mono">{_h(t['path'])}</td></tr><tr><th>Type / size</th><td>{_h(t['kind'])}, {t['size']:,} bytes</td></tr>
<tr><th>MD5</th><td class="mono">{_h(t['md5'])}</td></tr><tr><th>SHA-256</th><td class="mono">{_h(t['sha256'])}</td></tr>
{''.join(f"<tr><th>Stored {_h(k)}</th><td class='mono'>{_h(v)}</td></tr>" for k, v in (t.get('stored_hashes') or {}).items())}</table>
<h2>Known files ({sum(1 for k in r['known_files'] if k['status'] == 'recovered')} of {len(r['known_files'])} recovered byte-for-byte)</h2>
<table><tr><th>File</th><th>Size</th><th>SHA-256</th><th>Result</th><th>Offset</th><th>Length is</th><th>Note</th></tr>{krows}</table>
<h2>Unexpected items ({len(r['unexpected'])})</h2>
{'<p>None.</p>' if not r['unexpected'] else '<table><tr><th>#</th><th>Offset</th><th>Length</th><th>Length is</th><th>SHA-256</th><th>Notes</th></tr>' + urows + '</table>'}
<h2>Negative control</h2>{neg_html}
<h2>Vendored components</h2><p>{', '.join(f"{_h(v['name'])} {_h(v['version'])} ({'byte-identical' if v['ok'] else 'CHANGED'})" for v in r['tool']['vendored'])}</p>
<h2>Signature definition tested</h2><pre>{_h(json.dumps(r['signature'], indent=2))}</pre>
</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")
    return Path(path)
