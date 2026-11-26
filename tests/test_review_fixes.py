"""Regression tests for the issues found in the 2026-11-26 code review."""
import csv
import hashlib
import json
import threading
import time
from pathlib import Path

import pytest

from dfx.carve import Carver, CarveOptions, SignatureLibrary
from dfx.clock import DvrStore
from dfx.source import Source, open_source
from tests.fixtures import build_image

HF = {"id": "hf", "name": "hf", "header": "43 41 4D 53 54 41 52 54", "mode": "header_footer",
      "footer": "43 41 4D 45 4E 44 21", "max_size": 100000}


def _carve(src_path, sigs, out, **kw):
    with open_source(str(src_path)) as src:
        c = Carver(src, sigs, CarveOptions(out_dir=str(out), **kw))
        c.run()
    return c


# 1 -------------------------------------------------- maxsize must not hide items
def test_maxsize_does_not_hide_following_items(tmp_path):
    disk = bytearray(8 << 20)
    planted = [0x1000, 0x40000, 0x90000, 0x300000]
    for o in planted:
        disk[o:o + 4] = b"IMKH"
    img = tmp_path / "hik.img"
    img.write_bytes(disk)
    sig = dict(SignatureLibrary(tmp_path / "u").get("hik-imkh"), max_size=1 << 20, min_size=16)
    c = _carve(img, [sig], tmp_path / "o", dry_run=True)
    assert [i.start for i in c.items] == planted
    # each estimated item ends at the next export, not 1 MB later
    assert [i.end for i in c.items][:2] == [0x40000, 0x90000]
    assert all("end estimated" in i.notes for i in c.items)


# 2 -------------------------------------------------- crash-safe, idempotent resume
def test_resume_after_crash_has_no_duplicates(tmp_path):
    img = build_image(tmp_path / "img")["image"]
    sigs = SignatureLibrary(tmp_path / "u").all()
    for s in sigs:
        s["enabled"] = True
    out = tmp_path / "out"
    first = _carve(img, sigs, out, chunk_size=4096)
    ck = json.loads((out / "checkpoint.json").read_text())
    ck["next_offset"], ck["last_end"] = 0, {}          # crash: last checkpoint was at 0
    (out / "checkpoint.json").write_text(json.dumps(ck))
    (out / "carved" / "avi-riff" / "000099_off000000000000.avi.part").write_bytes(b"junk")
    r = _carve(img, sigs, out, chunk_size=1 << 20, dry_run=True, resume=True)
    rows = list(csv.DictReader(open(out / "carve_log.csv", encoding="utf-8")))
    assert len(rows) == len(first.items)
    assert not list(out.rglob("*.part"))
    assert r.opt.dry_run is False and r.opt.chunk_size == 4096      # original options kept
    assert sum(r.stats.per_signature.values()) == len(first.items)


def test_logged_part_file_is_recovered(tmp_path):
    img = build_image(tmp_path / "img")["image"]
    sigs = [SignatureLibrary(tmp_path / "u").get("avi-riff")]
    out = tmp_path / "out"
    c = _carve(img, sigs, out)
    f = out / c.items[0].file
    f.rename(f.with_name(f.name + ".part"))           # crash between CSV row and rename
    _carve(img, sigs, out, resume=True)
    assert f.exists() and hashlib.sha256(f.read_bytes()).hexdigest() == c.items[0].sha256


# 3 -------------------------------------------------- overlapping header candidates
def test_overlapping_header_candidates(tmp_path):
    img = tmp_path / "o.img"
    img.write_bytes(b"\x00" * 10 + b"\xAA\x55" + b"\xAA\x55\xAA\x55" + b"\x00" * 100)
    sig = {"id": "ov", "name": "ov", "header": "AA 55 AA 55", "mode": "header_maxsize",
           "max_size": 4, "min_size": 4}
    c = _carve(img, [sig], tmp_path / "o", dry_run=True)
    # the real header at 12 is found; the junk candidate at 10 is cut at 12 and rejected (< min_size)
    assert [i.start for i in c.items] == [12]


# 5 -------------------------------------------------- short reads
class _Short(Source):
    kind, path, sector_size = "mock", "mock", 512

    def __init__(self, data):
        self.d, self.size = data, len(data)

    def read_at(self, off, n):
        return self.d[off:off + min(n, 3000)]


def test_short_reads_do_not_skip_data(tmp_path):
    data = bytearray(64 * 1024)
    data[40000:40008], data[40500:40507] = b"CAMSTART", b"CAMEND!"
    c = Carver(_Short(bytes(data)), [HF], CarveOptions(out_dir=str(tmp_path / "o"), chunk_size=8192, dry_run=True))
    st = c.run()
    assert [(i.start, i.length) for i in c.items] == [(40000, 507)]
    assert st.scanned == st.total and not st.read_errors


def test_dead_source_is_reported(tmp_path):
    class Dead(_Short):
        def read_at(self, off, n):
            return b"" if off >= 16384 else super().read_at(off, n)
    c = Carver(Dead(bytes(64 * 1024)), [HF], CarveOptions(out_dir=str(tmp_path / "o"), chunk_size=8192, dry_run=True))
    st = c.run()
    assert st.read_errors and st.scanned < st.total


# 6 -------------------------------------------------- DvrStore concurrency
def test_dvrstore_parallel_writes(tmp_path):
    d = DvrStore(tmp_path).save_dvr({"name": "NVR"})

    def add(i):
        DvrStore(tmp_path).add_measurement(d["id"], {"dvr_time": f"2026-11-26 08:{i % 60:02d}:00",
                                                     "reference_time": "2026-11-26 08:00:00"})
    ts = [threading.Thread(target=add, args=(i,)) for i in range(40)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(DvrStore(tmp_path).get(d["id"])["measurements"]) == 40


# 4 / 7 ---------------------------------------------- server job isolation, test cap
def test_evidence_locked_while_job_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "app"))
    import dfx.server as srv
    real = srv.hash_source
    monkeypatch.setattr(srv, "hash_source", lambda s, **kw: (time.sleep(0.4), real(s, **kw))[1])
    a_img, b_img = tmp_path / "A.img", tmp_path / "B.img"
    a_img.write_bytes(b"A" * 100000)
    b_img.write_bytes(b"B" * 10)
    app = srv.App()
    app.open_case({"folder": str(tmp_path / "case")})
    app.set_source(str(a_img))
    app.start_hash()
    time.sleep(0.05)
    with pytest.raises(RuntimeError):
        app.set_source(str(b_img))
    with pytest.raises(RuntimeError):
        app.open_case({"folder": str(tmp_path / "case2")})
    while app.job["running"]:
        time.sleep(0.02)
    assert app.evidence_hash["path"] == str(a_img)
    assert app.evidence_hash["sha256"] == hashlib.sha256(a_img.read_bytes()).hexdigest()


def test_signature_test_is_capped(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "app"))
    from dfx.server import App
    img = tmp_path / "x.img"
    disk = bytearray(1 << 20)
    disk[0x1000:0x1004] = disk[0x80000:0x80004] = b"IMKH"
    img.write_bytes(disk)
    r = App().test_signature({"id": "x", "name": "x", "header": "49 4D 4B 48", "mode": "header_maxsize",
                              "max_size": 4096}, str(img), max_bytes=0x40000)
    assert [i["start"] for i in r["items"]] == [0x1000] and r["capped"]


def test_report_flags_unhashed_evidence(tmp_path):
    img = build_image(tmp_path / "img")["image"]
    out = tmp_path / "out"
    _carve(img, [SignatureLibrary(tmp_path / "u").get("avi-riff")], out)
    from dfx.report import build_report
    assert "Evidence not hashed" in build_report(out).read_text(encoding="utf-8")
