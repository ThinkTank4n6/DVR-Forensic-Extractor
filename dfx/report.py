"""HTML report for a carve run (built from carve_session.json + carve_log.csv)."""
from __future__ import annotations

import csv
import datetime as _dt
import html
import json
from pathlib import Path

from . import APP_NAME, __version__
from .clock import convert, drift_fit, describe_offset


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

    warn = ("<div class='warn'><b>Early development build of DFX &mdash; not yet tested on real DVR evidence.</b> "
            "Results must be independently verified.</div>")
    if unvalidated:
        warn += ("<div class='warn'><b>Unvalidated signatures used:</b> "
                 + ", ".join(_h(s["name"]) for s in unvalidated)
                 + ". Results from these signatures have not been checked against known test data "
                   "with this version of the tool.</div>")
    if not (evidence_hash or {}).get("sha256"):
        warn += ("<div class='warn'><b>Evidence not hashed in DFX.</b> No MD5/SHA-256 was calculated for this "
                 "source before the report was built; compare against your acquisition hash.</div>")
    if st.get("read_errors"):
        warn += ("<div class='warn'><b>Read problems during the scan:</b><br>"
                 + "<br>".join(_h(e) for e in st["read_errors"][:50])
                 + ("<br>&hellip;" if len(st["read_errors"]) > 50 else "") + "</div>")
    if int(st.get("scanned", 0)) < int(st.get("total", 0)) and not st.get("canceled"):
        warn += (f"<div class='warn'><b>Scan incomplete:</b> {int(st['scanned']):,} of {int(st['total']):,} "
                 "bytes were scanned.</div>")
    if st.get("canceled"):
        warn += "<div class='warn'><b>Scan was canceled before the end of the range.</b></div>"
    if sess["options"].get("dry_run"):
        warn += "<div class='warn'>Dry run: items were logged, not copied out.</div>"

    ev = ""
    stored = src.get("stored_hashes") or {}
    if stored:
        ev += "".join(f"<tr><th>Acquisition {k} (stored in image)</th><td class='mono'>{_h(v)}</td></tr>"
                      for k, v in stored.items())
    if evidence_hash and evidence_hash.get("stored_match") is not None:
        ev += ("<tr><th>Stored hash check</th><td>" + ("Matches the data DFX read" if evidence_hash["stored_match"]
               else "<span class='bad'>DOES NOT MATCH the data DFX read</span>") + "</td></tr>")
    if evidence_hash:
        ev += (f"<tr><th>MD5</th><td class='mono'>{_h(evidence_hash.get('md5'))}</td></tr>"
              f"<tr><th>SHA-256</th><td class='mono'>{_h(evidence_hash.get('sha256'))}</td></tr>"
              f"<tr><th>Hashed</th><td>{_h(evidence_hash.get('when'))}</td></tr>")

    sig_rows = "".join(
        f"<tr><td>{_h(s['name'])}</td><td class='mono'>{_h(s['id'])}</td><td>{_h(s['mode'])}</td>"
        f"<td class='mono'>{_h(s['header'])}</td><td class='mono'>{_h(s.get('footer'))}</td>"
        f"<td>{'Yes' if s.get('validated') else '<span class=bad>No</span>'}</td>"
        f"<td>{st['per_signature'].get(s['id'], 0)}</td></tr>" for s in sess["signatures"])

    clock = sess.get("clock")
    clock_html, notes_seen = "", []

    def _actual(t):
        if not clock or not t:
            return ""
        try:
            r = convert(clock, t, "dvr_to_actual")
        except Exception as e:  # noqa: BLE001
            return f"(not converted: {e})"
        for n in r["notes"]:
            if n not in notes_seen:
                notes_seen.append(n)
        return r["actual_time"]

    def _times(r):
        if not clock:
            return f"<td>{_h(r['first_time'])}</td><td>{_h(r['last_time'])}</td>"
        return (f"<td>{_h(r['first_time'])}<br><b>{_h(_actual(r['first_time']))}</b></td>"
                f"<td>{_h(r['last_time'])}<br><b>{_h(_actual(r['last_time']))}</b></td>")

    item_rows = "".join(
        f"<tr><td>{_h(r['item_no'])}</td><td>{_h(r['signature_name'])}</td>"
        f"<td class='mono'>{_h(r['start_hex'])}</td><td class='num'>{int(r['start']):,}</td>"
        f"<td class='num'>{int(r['length']):,}<br><span class='small'>{_h(r.get('bounded', ''))}</span></td><td>{_h(r['status'])}</td>"
        f"<td>{_h(r['frames'] if r['frames'] != '0' else '')}</td><td>{_h(r['channels'])}</td>"
        + _times(r) +
        f"<td class='mono small'>{_h(r['file'])}<br>MD5 {_h(r['md5'])}<br>SHA-256 {_h(r['sha256'])}</td>"
        f"<td class='small'>{_h(r['notes'])}</td></tr>" for r in rows)

    if clock:
        ms = clock.get("measurements") or []
        mrows = "".join(f"<tr><td>{_h(m['dvr_time'])}</td><td>{_h(m['reference_time'])}</td>"
                        f"<td>{_h(m['offset_text'])}</td><td>{_h(m['reference_source'])}</td>"
                        f"<td>{_h(m.get('examiner'))}</td><td>{_h(m['recorded'])}</td></tr>" for m in ms)
        clock_html = (f"<h2>DVR clock offset</h2><table class='kv'><tr><th>Recorder</th><td>{_h(clock.get('name'))} "
                      f"{_h(clock.get('make'))} {_h(clock.get('model'))} {_h(clock.get('serial'))}</td></tr>"
                      f"<tr><th>Recorder DST setting</th><td>{_h(clock.get('dst_setting') or 'not recorded')}</td></tr></table>"
                      "<table><tr><th>DVR time</th><th>Reference time</th><th>Offset</th><th>Reference source</th>"
                      f"<th>Examiner</th><th>Recorded</th></tr>{mrows}</table>"
                      "<p class='small sub'>In the item table, the first line of each time is the device time as recorded; "
                      "the <b>bold</b> line is the estimated actual time after removing the clock offset.</p>"
                      + "".join(f"<div class='warn'>{_h(n)}</div>" for n in notes_seen))

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
<tr><th>Access</th><td>Opened read-only by {_h(APP_NAME)}{(" via " + _h(src.get("reader"))) if src.get("reader") else ""}</td></tr></table>
<h2>Scan</h2><table class="kv">
<tr><th>Range</th><td>{int(sess['range']['start']):,} &ndash; {int(sess['range']['end']):,}</td></tr>
<tr><th>Started / finished</th><td>{_h(st['started'])} / {_h(st['finished'])}</td></tr>
<tr><th>Elapsed</th><td>{float(st['elapsed']):,.1f} s</td></tr>
<tr><th>Bytes scanned</th><td>{int(st['scanned']):,}</td></tr>
<tr><th>Items</th><td>{st['items']} ({_size(st['bytes_carved'])})</td></tr>
<tr><th>Rejected header hits</th><td>{st['rejected']}</td></tr>
<tr><th>Sector-aligned only</th><td>{'Yes' if sess['options'].get('force_sector_aligned') else 'Per signature'}</td></tr>
<tr><th>Signature set SHA-256</th><td class="mono">{_h(sess['signatures_sha256'])}</td></tr>
<tr><th>Length judge</th><td>{_h((sess.get('length_judge') or {}).get('name', 'none'))} {_h((sess.get('length_judge') or {}).get('version', ''))}</td></tr></table>
<p class="small sub"><b>Length</b> column: <i>header</i> = the file's own header recorded the length; <i>parsed</i> = found by walking the file's structure; <i>capped</i> = the end was not confirmed, so the length is a ceiling, not a fact.</p>
<h2>Signatures</h2><table><tr><th>Name</th><th>ID</th><th>Mode</th><th>Header</th><th>Footer</th><th>Validated</th><th>Items</th></tr>{sig_rows}</table>
{clock_html}<h2>Items</h2><table><tr><th>#</th><th>Signature</th><th>Offset</th><th>Offset (dec)</th><th>Length</th><th>Status</th><th>Frames</th><th>Ch</th><th>First time (device{" / actual" if clock else ""})</th><th>Last time (device{" / actual" if clock else ""})</th><th>File / hashes</th><th>Notes</th></tr>{item_rows or '<tr><td colspan=12>No items</td></tr>'}</table>
<p class="small sub">Device times are shown exactly as recorded by the recorder, with no time-zone or clock-offset correction.</p>
<h2>Signature definitions used</h2><pre>{sigs_json}</pre>
</body></html>"""
    out = run / "report.html"
    out.write_text(doc, encoding="utf-8")
    return out


def build_clock_report(dvr: dict, case: dict, out_path: str | Path, ref_status: dict | None = None) -> Path:
    """Offset worksheet for one recorder: measurements, drift and logged conversions."""
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ms = dvr.get("measurements") or []
    fit = drift_fit(ms) if len(ms) >= 2 else None
    mrows = "".join(
        f"<tr><td>{i + 1}</td><td class='mono'>{_h(m['dvr_time'])}</td><td class='mono'>{_h(m['reference_time'])}</td>"
        f"<td>{_h(m['offset_text'])}<br><span class='mono'>{m['offset_s']:+.0f} s</span></td>"
        f"<td>{_h(m['reference_source'])}<div class='small'>{_h((m.get('reference_status') or {}).get('sync_source', ''))} "
        f"{_h((m.get('reference_status') or {}).get('last_sync', ''))}</div></td>"
        f"<td>{_h(m.get('method'))}</td><td>{_h(m.get('examiner'))}</td><td>{_h(m['recorded'])}</td>"
        f"<td class='small'>{_h(m.get('notes'))}</td></tr>" for i, m in enumerate(ms))
    crow = "".join(
        f"<tr><td>{_h(c.get('label'))}</td><td>{'DVR → actual' if c['direction'] == 'dvr_to_actual' else 'Actual → DVR'}</td>"
        f"<td class='mono'>{_h(c['dvr_time'])}</td><td class='mono'><b>{_h(c['actual_time'])}</b></td>"
        f"<td class='mono'>{_h(c['offset_hms'])}</td><td class='small'>{_h(c['method'])}"
        + "".join(f"<div class='warnline'>{_h(n)}</div>" for n in c.get("notes", []))
        + f"</td><td>{_h(c['recorded'])}</td></tr>" for c in dvr.get("conversions", []))
    drift = ""
    if fit:
        drift = (f"<tr><th>Drift</th><td>{fit['rate_s_per_day']:+.3f} seconds per day "
                 f"({fit['rate_s_per_day'] * 7:+.1f} s/week), fitted over {fit['points']} measurements from "
                 f"{_h(fit['first'])} to {_h(fit['last'])}; largest deviation from the fit {fit['max_residual_s']:.1f} s</td></tr>")
    elif ms:
        drift = "<tr><th>Drift</th><td>Not measured (one measurement). The offset is assumed constant.</td></tr>"
    cur = describe_offset(ms[-1]["offset_s"]) if ms else "No measurements"
    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>DVR clock offset - {_h(dvr.get('name'))}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;color:#1d232b;margin:28px;font-size:13px}}
h1{{color:#20303f;margin:0}} h2{{color:#20303f;border-bottom:2px solid #e39a2d;padding-bottom:3px;margin-top:26px}}
table{{border-collapse:collapse;width:100%;margin-top:8px}} th,td{{border:1px solid #c9d0d8;padding:4px 6px;text-align:left;vertical-align:top}}
th{{background:#eef1f4}} .kv th{{width:210px}} .mono{{font-family:Consolas,monospace}} .small{{font-size:11px}}
.warn{{background:#fff4e0;border-left:4px solid #e39a2d;padding:8px;margin:8px 0}} .warnline{{color:#8a5a00;font-size:11px;margin-top:3px}}
.big{{font-size:18px;font-weight:600}} .sub{{color:#5b6773}}
</style></head><body>
<h1>DVR Clock Offset Worksheet</h1><div class="sub">{_h(APP_NAME)} {_h(__version__)} &middot; generated {now}</div>
<div class="warn"><b>Early development build of DFX &mdash; not yet tested on real DVR evidence.</b> Results must be independently verified.</div>
<h2>Case</h2><table class="kv"><tr><th>Case number</th><td>{_h(case.get('case_number'))}</td></tr>
<tr><th>Examiner</th><td>{_h(case.get('examiner'))}</td></tr><tr><th>Agency</th><td>{_h(case.get('agency'))}</td></tr></table>
<h2>Recorder</h2><table class="kv"><tr><th>Name / location</th><td>{_h(dvr.get('name'))} {_h(dvr.get('location'))}</td></tr>
<tr><th>Make / model / serial</th><td>{_h(dvr.get('make'))} {_h(dvr.get('model'))} {_h(dvr.get('serial'))}</td></tr>
<tr><th>Channels</th><td>{_h(dvr.get('channels'))}</td></tr>
<tr><th>DST setting on recorder</th><td>{_h(dvr.get('dst_setting') or 'not recorded')}</td></tr>
<tr><th>Notes</th><td>{_h(dvr.get('notes'))}</td></tr></table>
<h2>Offset</h2><table class="kv"><tr><th>Latest measured offset</th><td class="big">{_h(cur)}</td></tr>{drift}
<tr><th>Convention</th><td>Offset = DVR time &minus; actual time. Actual = DVR &minus; offset. DVR = actual + offset.</td></tr></table>
<h2>Measurements</h2><table><tr><th>#</th><th>DVR time shown</th><th>Reference (actual) time</th><th>Offset</th><th>Reference source</th><th>Method</th><th>Examiner</th><th>Recorded</th><th>Notes</th></tr>
{mrows or '<tr><td colspan=9>None</td></tr>'}</table>
<h2>Time conversions</h2><table><tr><th>Event</th><th>Direction</th><th>DVR time</th><th>Actual time</th><th>Offset used</th><th>Method / notes</th><th>Recorded</th></tr>
{crow or '<tr><td colspan=7>None logged</td></tr>'}</table>
<p class="small sub">Times are local wall-clock times as displayed. Daylight-saving checks use the examining workstation's time zone.</p>
</body></html>"""
    out = Path(out_path)
    out.write_text(doc, encoding="utf-8")
    return out
