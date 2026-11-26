"""Vendored modules (byte-identical), E01 through ewfprobe, mediacarve length judge."""
import hashlib
import os
import shutil
import subprocess

import pytest

from dfx import vendored
from dfx.carve import Carver, CarveOptions, SignatureLibrary
from dfx.source import open_source
from tests.ewfwriter import write_ewf
from tests.fixtures import build_image, ffmpeg_ok


def test_vendored_files_are_byte_identical():
    res = vendored.verify()
    assert {r["name"] for r in res} == {"mediacarve", "ewfprobe"}
    assert all(r["ok"] for r in res), res


def _sigs(tmp_path, ids):
    lib = SignatureLibrary(tmp_path / "u")
    return [dict(lib.get(i)) for i in ids]


def _carve(path, sigs, out, **kw):
    with open_source(str(path)) as src:
        c = Carver(src, sigs, CarveOptions(out_dir=str(out), **kw))
        c.run()
    return c


# ------------------------------------------------------------------ E01
def test_e01_carves_identically_to_raw(tmp_path):
    info = build_image(tmp_path / "img")
    raw = info["image"].read_bytes()
    (tmp_path / "e01").mkdir()
    seg = write_ewf(tmp_path / "e01", "dvr", raw, chunks_per_segment=7)
    sigs = SignatureLibrary(tmp_path / "u").all()
    for s in sigs:
        s["enabled"] = True
    a = _carve(info["image"], sigs, tmp_path / "raw")
    b = _carve(seg[0], sigs, tmp_path / "e01out")
    assert [(i.signature_id, i.start, i.length, i.sha256) for i in a.items] == \
           [(i.signature_id, i.start, i.length, i.sha256) for i in b.items]
    with open_source(seg[0]) as s:
        assert s.kind == "e01" and len(seg) > 1
        assert s.describe()["stored_hashes"]["MD5"] == hashlib.md5(s.read_full(0, s.size)).hexdigest()


# ------------------------------------------------------------------ judge
def _video(tmp_path, ext, codec):
    p = tmp_path / f"v.{ext}"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i",
                    "testsrc=size=160x120:rate=10:duration=2", "-c:v", codec, str(p)], check=True)
    return p.read_bytes()


@pytest.mark.skipif(not ffmpeg_ok(), reason="ffmpeg not installed")
def test_mkv_length_is_parsed_not_guessed(tmp_path):
    mkv = _video(tmp_path, "mkv", "mjpeg")
    img = tmp_path / "d.img"
    img.write_bytes(os.urandom(3000) + mkv + os.urandom(5000) + mkv + os.urandom(3000))
    c = _carve(img, _sigs(tmp_path, ["mkv-ebml"]), tmp_path / "o")
    assert [i.length for i in c.items] == [len(mkv), len(mkv)]
    assert all(i.bounded in ("header", "parsed") for i in c.items)
    assert all((tmp_path / "o" / i.file).read_bytes() == mkv for i in c.items)


@pytest.mark.skipif(not ffmpeg_ok(), reason="ffmpeg not installed")
def test_fake_avi_header_cannot_hide_real_avi(tmp_path):
    avi = _video(tmp_path, "avi", "mjpeg")
    fake = b"RIFF" + (len(avi) + 50000).to_bytes(4, "little") + b"AVI " + os.urandom(500)
    img = tmp_path / "d.img"
    img.write_bytes(os.urandom(1000) + fake + avi + os.urandom(len(avi) + 60000))
    real_at = 1000 + len(fake)
    c = _carve(img, _sigs(tmp_path, ["avi-riff"]), tmp_path / "o", dry_run=True)
    real = [i for i in c.items if i.start == real_at]
    assert real and real[0].length == len(avi) and real[0].bounded in ("header", "parsed")
    fake_items = [i for i in c.items if i.start == 1000]
    assert all(i.bounded == "capped" and i.end <= real_at for i in fake_items)


@pytest.mark.skipif(not ffmpeg_ok(), reason="ffmpeg not installed")
def test_truncated_mp4_is_capped_and_hides_nothing(tmp_path):
    mp4 = _video(tmp_path, "mp4", "mjpeg")
    cut = mp4[: len(mp4) // 2]                     # recording interrupted / overwritten
    img = tmp_path / "d.img"
    img.write_bytes(os.urandom(2000) + cut + mp4 + os.urandom(4000))
    c = _carve(img, _sigs(tmp_path, ["mp4-iso"]), tmp_path / "o", dry_run=True)
    starts = {i.start: i for i in c.items}
    assert 2000 + len(cut) in starts and starts[2000 + len(cut)].length == len(mp4)
    assert starts[2000].bounded == "capped" and starts[2000].end == 2000 + len(cut)
    assert "overwritten" in starts[2000].notes


def test_session_records_judge_version(tmp_path):
    import json
    info = build_image(tmp_path / "img")
    _carve(info["image"], _sigs(tmp_path, ["mp4-iso"]), tmp_path / "o", dry_run=True)
    sess = json.loads((tmp_path / "o" / "carve_session.json").read_text())
    assert sess["length_judge"] == {"name": "mediacarve", "version": vendored.mediacarve().__version__}


def test_random_ftyp_is_not_carved(tmp_path):
    # 'ftyp' with a garbage size in unallocated space used to become a huge "truncated" MP4
    img = tmp_path / "d.img"
    blob = bytearray(os.urandom(2 << 20))
    blob[100000:100008] = (0x7A3B11C2).to_bytes(4, "big") + b"ftyp"
    img.write_bytes(blob)
    c = _carve(img, _sigs(tmp_path, ["mp4-iso"]), tmp_path / "o", dry_run=True)
    assert c.items == []


def test_hash_job_checks_stored_e01_hash(tmp_path, monkeypatch):
    import time
    monkeypatch.setenv("APPDATA", str(tmp_path / "app"))
    from dfx.server import App
    (tmp_path / "e").mkdir()
    seg = write_ewf(tmp_path / "e", "x", os.urandom(200000))
    app = App()
    app.open_case({"folder": str(tmp_path / "case")})
    app.set_source(seg[0])
    app.start_hash()
    while app.job["running"]:
        time.sleep(0.02)
    assert app.evidence_hash["stored"]["MD5"] == app.evidence_hash["md5"]
    assert app.evidence_hash["stored_match"] is True


def test_old_run_cannot_be_resumed_into(tmp_path):
    info = build_image(tmp_path / "img")
    out = tmp_path / "o"
    _carve(info["image"], _sigs(tmp_path, ["avi-riff"]), out)
    rows = (out / "carve_log.csv").read_text().splitlines()
    (out / "carve_log.csv").write_text("\n".join([rows[0].replace("bounded,", "")] + rows[1:]))
    with pytest.raises(ValueError, match="older version"):
        _carve(info["image"], _sigs(tmp_path, ["avi-riff"]), out, resume=True)


def test_report_shows_stored_hash_and_match(tmp_path):
    from dfx.report import build_report
    (tmp_path / "e").mkdir()
    data = build_image(tmp_path / "img")["image"].read_bytes()
    seg = write_ewf(tmp_path / "e", "x", data)
    out = tmp_path / "o"
    _carve(seg[0], _sigs(tmp_path, ["avi-riff"]), out)
    with open_source(seg[0]) as s:
        md5 = hashlib.md5(s.read_full(0, s.size)).hexdigest()
    html = build_report(out, {}, {"md5": md5, "sha256": "x", "stored_match": True, "path": seg[0]}).read_text()
    assert f"Acquisition MD5 (stored in image)</th><td class='mono'>{md5}" in html
    assert "Matches the data DFX read" in html and f"<td class='mono'>{md5}</td>" in html
