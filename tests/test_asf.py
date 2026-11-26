"""ASF / WMV structure walk (Dahua exports .asf)."""
import os
import subprocess

import pytest

from dfx.carve import Carver, CarveOptions, SignatureLibrary, asf
from dfx.learn import learn, sample_from_file
from dfx.source import open_source
from tests.fixtures import ffmpeg_ok

pytestmark = pytest.mark.skipif(not ffmpeg_ok(), reason="ffmpeg not installed")


def _asf(tmp_path, name, dur):
    p = tmp_path / name
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i",
                    f"testsrc=size=160x120:rate=10:duration={dur}", "-c:v", "mpeg4", "-f", "asf", str(p)], check=True)
    return p


def _carve(img, tmp_path, **kw):
    sig = dict(SignatureLibrary(tmp_path / "u").get("asf-wmv"))
    with open_source(str(img)) as src:
        c = Carver(src, [sig], CarveOptions(out_dir=str(tmp_path / "o"), **kw))
        c.run()
    return c


def test_walk_matches_file_size_and_reads_properties(tmp_path):
    p = _asf(tmp_path, "a.asf", 3)
    data = p.read_bytes()
    res = asf.walk(lambda o, n: data[o:o + n], 0, len(data))
    assert res["end"] == len(data) and res["objects"][:2] == ["header", "data"]
    assert res["properties"]["file_size"] == len(data)
    assert res["properties"]["duration_s"] == pytest.approx(3.0, abs=0.2)


def test_carves_back_to_back_asf_exactly(tmp_path):
    clips = [_asf(tmp_path, f"c{i}.asf", i + 1).read_bytes() for i in range(3)]
    blob, starts = bytearray(os.urandom(5000)), []
    for c in clips:
        starts.append(len(blob))
        blob += c                                   # back to back: no gap at all
    blob += os.urandom(5000)
    img = tmp_path / "d.img"
    img.write_bytes(blob)
    c = _carve(img, tmp_path)
    assert [(i.start, i.length, i.bounded) for i in c.items] == [(s, len(x), "parsed") for s, x in zip(starts, clips)]
    assert all((tmp_path / "o" / i.file).read_bytes() == x for i, x in zip(c.items, clips))
    assert "header file size matches" in c.items[0].notes


def test_overwritten_asf_is_cut_and_newer_file_kept(tmp_path):
    old = _asf(tmp_path, "old.asf", 4).read_bytes()
    new = _asf(tmp_path, "new.asf", 1).read_bytes()
    cut = len(old) // 2
    img = tmp_path / "d.img"
    img.write_bytes(os.urandom(3000) + old[:cut] + new + os.urandom(len(old)))
    c = _carve(img, tmp_path, dry_run=True)
    got = {i.start: i for i in c.items}
    assert got[3000].bounded == "capped" and got[3000].end == 3000 + cut and "overwritten" in got[3000].notes
    assert got[3000 + cut].length == len(new) and got[3000 + cut].bounded == "parsed"


def test_random_asf_guid_is_not_carved(tmp_path):
    blob = bytearray(os.urandom(1 << 20))
    blob[5000:5016] = asf.HEADER                    # GUID with a garbage size after it
    img = tmp_path / "d.img"
    img.write_bytes(blob)
    assert _carve(img, tmp_path, dry_run=True).items == []


def test_learner_recognizes_asf_exports(tmp_path):
    r = learn([sample_from_file(str(_asf(tmp_path, f"e{i}.asf", i + 1))) for i in range(2)])
    assert r["recognized"] == {"kind": "asf", "builtin": "asf-wmv"}
    assert "asf-wmv" in r["warnings"][0]
