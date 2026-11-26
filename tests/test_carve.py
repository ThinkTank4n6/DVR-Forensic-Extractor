import csv
import hashlib
import json

import pytest

from dfx.source import open_source, hash_source
from dfx.carve import Carver, CarveOptions, SignatureLibrary, check, decode_timestamp
from dfx.carve.signatures import parse_hex, SignatureError
from tests.fixtures import build_image, ffmpeg_ok, dahua_packed

HF_SIG = {"id": "test-hf", "name": "Test header/footer", "extension": "bin",
          "header": "43 41 4D 53 54 41 52 54", "mode": "header_footer",
          "footer": "43 41 4D 45 4E 44 21", "max_size": 100000}


@pytest.fixture(scope="module")
def image(tmp_path_factory):
    return build_image(tmp_path_factory.mktemp("img"))


def _sigs(tmp_path, enable_dhav=True):
    lib = SignatureLibrary(tmp_path / "usersigs")
    lib.save_user(HF_SIG)
    sigs = []
    for s in lib.all():
        if s["id"] == "dahua-dhav":
            s["enabled"] = enable_dhav
        if s["enabled"] and not s["problems"]:
            sigs.append(s)
    return sigs


def _run(image, tmp_path, **kw):
    out = tmp_path / "out"
    with open_source(str(image["image"])) as src:
        c = Carver(src, _sigs(tmp_path), CarveOptions(out_dir=str(out), chunk_size=1024 * 1024, **kw))
        c.run()
    return c, out


def test_builtin_signatures_are_valid(tmp_path):
    for s in SignatureLibrary(tmp_path).all():
        assert not s.get("problems"), (s["id"], s["problems"])


def test_hex_parsing():
    assert parse_hex("52 49 ?? 46") == [0x52, 0x49, None, 0x46]
    assert parse_hex("5249") == [0x52, 0x49]
    with pytest.raises(SignatureError):
        parse_hex("5G")


def test_check_catches_bad_signatures():
    assert check({"id": "x", "name": "x", "header": "?? ??", "mode": "header_maxsize"})
    assert check({"id": "x", "name": "x", "header": "AA BB", "mode": "header_footer"})
    assert check({"id": "x", "name": "x", "header": "AA BB", "mode": "header_length"})
    assert not check({"id": "ok", "name": "ok", "header": "AA BB", "mode": "header_maxsize"})


def test_dahua_packed_decode():
    assert decode_timestamp(dahua_packed(2026, 11, 25, 14, 3, 9), "dahua_packed") == "2026-11-25 14:03:09"


def test_finds_every_planted_item_exactly(image, tmp_path):
    c, out = _run(image, tmp_path)
    found = {(i.signature_id, i.start, i.length) for i in c.items}
    for t in image["truth"]:
        assert (t["sig"], t["start"], t["length"]) in found, t
    # every carved file matches the bytes in the image
    raw = image["image"].read_bytes()
    for i in c.items:
        data = (out / i.file).read_bytes()
        assert data == raw[i.start:i.end]
        assert hashlib.sha256(data).hexdigest() == i.sha256


def test_dhav_chain_metadata(image, tmp_path):
    c, _ = _run(image, tmp_path)
    t = next(x for x in image["truth"] if x["sig"] == "dahua-dhav")
    it = next(i for i in c.items if i.signature_id == "dahua-dhav" and i.start == t["start"])
    assert it.frames == 40
    assert it.channels == "2"
    assert it.first_time == t["first_time"] and it.last_time == t["last_time"]
    # the 39 inner frame headers were not carved again
    assert sum(1 for i in c.items if i.signature_id == "dahua-dhav") == 1


@pytest.mark.skipif(not ffmpeg_ok(), reason="ffmpeg not installed")
def test_carved_mp4_and_avi_play(image, tmp_path):
    import subprocess
    c, out = _run(image, tmp_path)
    for i in c.items:
        if i.signature_id in ("mp4-iso", "avi-riff"):
            r = subprocess.run(["ffprobe", "-v", "error", "-count_frames", "-select_streams", "v:0",
                                "-show_entries", "stream=nb_read_frames", "-of", "csv=p=0",
                                str(out / i.file)], capture_output=True, text=True)
            assert r.returncode == 0 and int(r.stdout.strip()) == 20


def test_chunk_boundaries_do_not_change_results(image, tmp_path):
    a, _ = _run(image, tmp_path / "a")
    out = tmp_path / "b" / "out"
    with open_source(str(image["image"])) as src:
        b = Carver(src, _sigs(tmp_path / "b"), CarveOptions(out_dir=str(out), chunk_size=1, dry_run=True))
        b.opt.chunk_size = 4097  # odd size forces headers to straddle chunks
        b.run()
    assert {(i.signature_id, i.start, i.length) for i in a.items} == \
           {(i.signature_id, i.start, i.length) for i in b.items}


def test_dry_run_writes_no_files(image, tmp_path):
    c, out = _run(image, tmp_path, dry_run=True)
    assert c.items and not (out / "carved").exists()
    assert all(i.status in ("logged", "incomplete") for i in c.items)


def test_resume_after_cancel(image, tmp_path):
    out = tmp_path / "out"
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] > 3

    with open_source(str(image["image"])) as src:
        c1 = Carver(src, _sigs(tmp_path), CarveOptions(out_dir=str(out), chunk_size=4096), cancel=cancel)
        s1 = c1.run()
        assert s1.canceled
        c2 = Carver(src, _sigs(tmp_path), CarveOptions(out_dir=str(out), chunk_size=4096, resume=True))
        c2.run()
    full, _ = _run(image, tmp_path / "full")
    assert {(i.signature_id, i.start) for i in c2.items} == {(i.signature_id, i.start) for i in full.items}
    rows = list(csv.DictReader(open(out / "carve_log.csv", encoding="utf-8")))
    assert len(rows) == len(full.items)


def test_refuses_to_overwrite_previous_carve(image, tmp_path):
    _run(image, tmp_path)
    with pytest.raises(FileExistsError):
        _run(image, tmp_path)


def test_source_is_not_modified(image, tmp_path):
    before = hashlib.sha256(image["image"].read_bytes()).hexdigest()
    _run(image, tmp_path)
    with open_source(str(image["image"])) as src:
        assert hash_source(src)["sha256"] == before


def test_session_records_signatures(image, tmp_path):
    _, out = _run(image, tmp_path)
    sess = json.loads((out / "carve_session.json").read_text())
    ids = {s["id"] for s in sess["signatures"]}
    assert "dahua-dhav" in ids and "test-hf" in ids
    assert len(sess["signatures_sha256"]) == 64


def test_split_raw(image, tmp_path):
    raw = image["image"].read_bytes()
    half = len(raw) // 2
    (tmp_path / "x.001").write_bytes(raw[:half])
    (tmp_path / "x.002").write_bytes(raw[half:])
    with open_source(str(tmp_path / "x.001")) as s:
        assert s.size == len(raw)
        assert s.read_at(half - 10, 20) == raw[half - 10: half + 10]


def test_broken_chain_splits_into_two_items(tmp_path):
    from tests.fixtures import dhav_chain
    a, b = dhav_chain(10, 1), dhav_chain(10, 1, start_sec=30)
    img = tmp_path / "broken.img"
    img.write_bytes(b"\x00" * 100 + a + b"\xFF" * 50 + b + b"\x00" * 100)
    lib = SignatureLibrary(tmp_path / "u")
    sig = dict(lib.get("dahua-dhav"))
    with open_source(str(img)) as src:
        c = Carver(src, [sig], CarveOptions(out_dir=str(tmp_path / "o")))
        c.run()
    assert [(i.start, i.frames) for i in c.items] == [(100, 10), (100 + len(a) + 50, 10)]
