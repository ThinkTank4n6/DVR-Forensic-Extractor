"""HTML report for a carve run (built from carve_session.json + carve_log.csv)."""
from __future__ import annotations

import csv
import datetime as _dt
import html
import json
from pathlib import Path

from . import APP_NAME, __version__


def _h(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _size(n) -> str:
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:,.0f} {u}" if u == "B" else f"{n:,.2f} {u}"
        n /= 1024
    return str(n)


def build_report(run_dir: str | Path, case: dict | None = None, evidence_hash: dict | None = None) -> Path:
    run = Path(run_dir)
    sess = json.loads((run / "carve_session.json").read_text(encoding="utf-8"))
    rows = []
    if (run / "carve_log.csv").exists():
        with open(run / "carve_log.csv", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    case = case or {}
    st = sess["stats"]
    src = sess["source"]
    unvalidated = [s for s in sess["signatures"] if not s.get("validated")]
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    warn = ""
    if unvalidated:
        warn += ("<div class='warn'><b>Unvalidated signatures used:</b> "
                 + ", ".join(_h(s["name"]) for s in unvalidated)
                 + ". Results from these signatures have not been checked against known test data "
                   "with this version of the tool.</div>")
    if st.get("canceled"):
        warn += "<div class='warn'><b>Scan was canceled before the end of the range.</b></div>"
    if sess["options"].get("dry_run"):
        warn += "<div class='warn'>Dry run: items were logged, not copied out.</div>"

    ev = ""
    if evidence_hash:
        ev = (f"<tr><th>MD5</th><td class='mono'>{_h(evidence_hash.get('md5'))}</td></tr>"
              f"<tr><th>SHA-256</th><td class='mono'>{_h(evidence_hash.get('sha256'))}</td></tr>"
              f"<tr><th>Hashed</th><td>{_h(evidence_hash.get('when'))}</td></tr>")

    sig_rows = "".join(
        f"<tr><td>{_h(s['name'])}</td><td class='mono'>{_h(s['id'])}</td><td>{_h(s['mode'])}</td>"
        f"<td class='mono'>{_h(s['header'])}</td><td class='mono'>{_h(s.get('footer'))}</td>"
        f"<td>{'Yes' if s.get('validated') else '<span class=bad>No</span>'}</td>"
        f"<td>{st['per_signature'].get(s['id'], 0)}</td></tr>" for s in sess["signatures"])

    item_rows = "".join(
        f"<tr><td>{_h(r['item_no'])}</td><td>{_h(r['signature_name'])}</td>"
        f"<td class='mono'>{_h(r['start_hex'])}</td><td class='num'>{int(r['start']):,}</td>"
        f"<td class='num'>{int(r['length']):,}</td><td>{_h(r['status'])}</td>"
        f"<td>{_h(r['frames'] if r['frames'] != '0' else '')}</td><td>{_h(r['channels'])}</td>"
        f"<td>{_h(r['first_time'])}</td><td>{_h(r['last_time'])}</td>"
        f"<td class='mono small'>{_h(r['file'])}<br>MD5 {_h(r['md5'])}<br>SHA-256 {_h(r['sha256'])}</td>"
        f"<td class='small'>{_h(r['notes'])}</td></tr>" for r in rows)

    sigs_json = _h(json.dumps(sess["signatures"], indent=2))

    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>{_h(APP_NAME)} report - {_h(case.get('case_number', ''))}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;color:#1d232b;margin:28px;font-size:13px}}
h1{{color:#20303f;margin:0}} h2{{color:#20303f;border-bottom:2px solid #e39a2d;padding-bottom:3px;margin-top:28px}}
table{{border-collapse:collapse;width:100%;margin-top:8px}} th,td{{border:1px solid #c9d0d8;padding:4px 6px;text-align:left;vertical-align:top}}
th{{background:#eef1f4}} .kv th{{width:200px}} .mono{{font-family:Consolas,monospace}} .small{{font-size:11px}}
.num{{text-align:right}} .warn{{background:#fff4e0;border-left:4px solid #e39a2d;padding:8px;margin:8px 0}}
.bad{{color:#b3261e;font-weight:600}} pre{{background:#f6f7f9;padding:10px;font-size:11px;overflow:auto}}
.sub{{color:#5b6773}}
</style></head><body>
<h1>{_h(APP_NAME)} &mdash; Carving Report</h1>
<div class="sub">Version {_h(__version__)} &middot; generated {now}</div>
{warn}
<h2>Case</h2><table class="kv">
<tr><th>Case number</th><td>{_h(case.get('case_number'))}</td></tr>
<tr><th>Examiner</th><td>{_h(case.get('examiner'))}</td></tr>
<tr><th>Agency</th><td>{_h(case.get('agency'))}</td></tr>
<tr><th>Description</th><td>{_h(case.get('description'))}</td></tr></table>
<h2>Evidence</h2><table class="kv">
<tr><th>Source</th><td class="mono">{_h(src['path'])}</td></tr>
<tr><th>Type</th><td>{_h(src['kind'])}</td></tr>
<tr><th>Size</th><td>{int(src['size']):,} bytes ({_size(src['size'])})</td></tr>
<tr><th>Sector size</th><td>{_h(src['sector_size'])}</td></tr>{ev}
<tr><th>Access</th><td>Opened read-only by {_h(APP_NAME)}</td></tr></table>
<h2>Scan</h2><table class="kv">
<tr><th>Range</th><td>{int(sess['range']['start']):,} &ndash; {int(sess['range']['end']):,}</td></tr>
<tr><th>Started / finished</th><td>{_h(st['started'])} / {_h(st['finished'])}</td></tr>
<tr><th>Elapsed</th><td>{float(st['elapsed']):,.1f} s</td></tr>
<tr><th>Bytes scanned</th><td>{int(st['scanned']):,}</td></tr>
<tr><th>Items</th><td>{st['items']} ({_size(st['bytes_carved'])})</td></tr>
<tr><th>Rejected header hits</th><td>{st['rejected']}</td></tr>
<tr><th>Sector-aligned only</th><td>{'Yes' if sess['options'].get('force_sector_aligned') else 'Per signature'}</td></tr>
<tr><th>Signature set SHA-256</th><td class="mono">{_h(sess['signatures_sha256'])}</td></tr></table>
<h2>Signatures</h2><table><tr><th>Name</th><th>ID</th><th>Mode</th><th>Header</th><th>Footer</th><th>Validated</th><th>Items</th></tr>{sig_rows}</table>
<h2>Items</h2><table><tr><th>#</th><th>Signature</th><th>Offset</th><th>Offset (dec)</th><th>Length</th><th>Status</th><th>Frames</th><th>Ch</th><th>First time (device)</th><th>Last time (device)</th><th>File / hashes</th><th>Notes</th></tr>{item_rows or '<tr><td colspan=12>No items</td></tr>'}</table>
<p class="small sub">Device times are shown exactly as recorded by the recorder, with no time-zone or clock-offset correction.</p>
<h2>Signature definitions used</h2><pre>{sigs_json}</pre>
</body></html>"""
    out = run / "report.html"
    out.write_text(doc, encoding="utf-8")
    return out
