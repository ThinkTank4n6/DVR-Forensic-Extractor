"""Hex viewer, find, learner and Open-dialog endpoints (through the App the GUI uses)."""
import hashlib

import pytest

from tests.fixtures import build_image, dhav_chain


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "app"))
    from dfx.server import App
    a = App()
    a.open_case({"folder": str(tmp_path / "case")})
    return a


def test_hex_read_is_capped_and_read_only(app, tmp_path):
    info = build_image(tmp_path / "img")
    before = hashlib.sha256(info["image"].read_bytes()).hexdigest()
    app.set_source(str(info["image"]))
    r = app.hex_read({"target": "evidence", "offset": 100, "length": 10 ** 9})
    assert len(bytes.fromhex(r["hex"])) == app.HEX_MAX
    assert bytes.fromhex(r["hex"]) == info["image"].read_bytes()[100:100 + app.HEX_MAX]
    end = app.hex_read({"target": "evidence", "offset": info["size"] + 999, "length": 16})
    assert end["offset"] == info["size"] - 1
    assert hashlib.sha256(info["image"].read_bytes()).hexdigest() == before


def test_hex_find_hex_text_and_chunk_boundary(app, tmp_path):
    img = tmp_path / "f.img"
    data = bytearray(40 * 1024 * 1024)
    at = 32 * 1024 * 1024 - 2                       # straddles the 32 MB search chunk
    data[at:at + 4] = b"DHAV"
    data[1000:1005] = b"Hello"
    img.write_bytes(data)
    assert app.hex_find({"target": "file", "path": str(img), "query": "44 48 41 56"})["found"] == at
    assert app.hex_find({"target": "file", "path": str(img), "query": "4448??56"})["found"] == at
    assert app.hex_find({"target": "file", "path": str(img), "query": "hello", "mode": "text", "nocase": True})["found"] == 1000
    r = app.hex_find({"target": "file", "path": str(img), "query": "44 48 41 56", "offset": at + 1})
    assert r["found"] is None and r["end_of_source"]


def test_learn_from_files_and_evidence_range(app, tmp_path):
    paths = []
    for c in (1, 2, 3):
        p = tmp_path / f"c{c}.dav"
        p.write_bytes(dhav_chain(25, c, start_sec=c * 9))
        paths.append(p)
    r = app.learn({"samples": [{"kind": "file", "path": str(p)} for p in paths]})
    assert r["signature"]["mode"] == "frame_chain" and r["self_test"]["passed"]
    info = build_image(tmp_path / "img")
    app.set_source(str(info["image"]))
    t = next(x for x in info["truth"] if x["sig"] == "dahua-dhav")
    r2 = app.learn({"samples": [{"kind": "evidence", "offset": t["start"], "length": t["length"]}]})
    assert r2["signature"]["length_field"]["offset"] == 12
    assert any("Only 1 sample" in w for w in r2["warnings"])
    with pytest.raises(ValueError):
        app.learn({"samples": [{"kind": "evidence", "offset": 0, "length": 10 ** 10}]})
    assert "Signature learner ran" in (tmp_path / "case" / "case_log.txt").read_text()


def test_native_pick_reports_errors_instead_of_crashing(monkeypatch):
    import subprocess
    import dfx.server as srv

    class R:
        returncode, stdout, stderr = 1, '{"error": "tkinter is not available"}', ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: R())
    out = srv.native_pick("file")
    assert out["paths"] == [] and "tkinter" in out["error"]
