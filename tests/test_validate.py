"""Validate: PASS only when every known file is recovered byte-for-byte; marking is locked to the
exact definition tested, the DFX version, and an untouched report."""
import json
import os
import subprocess
import time

import pytest

from tests.fixtures import ffmpeg_ok

pytestmark = pytest.mark.skipif(not ffmpeg_ok(), reason="ffmpeg not installed")


def _asf(path, dur):
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i",
                    f"testsrc=size=160x120:rate=10:duration={dur}", "-c:v", "mpeg4", "-f", "asf", str(path)],
                   check=True)
    return path


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Known exports, a 'USB stick' image holding them (one deleted = still in the bytes), a clean drive."""
    monkeypatch.setenv("APPDATA", str(tmp_path / "app"))
    known = [_asf(tmp_path / f"exp{i}.asf", i + 1) for i in range(3)]
    usb = bytearray(os.urandom(64 * 1024))
    for k in known:
        usb += k.read_bytes() + os.urandom(7000)
    (tmp_path / "usb.img").write_bytes(usb)
    (tmp_path / "clean.img").write_bytes(os.urandom(2 << 20))
    from dfx.server import App
    app = App()
    app.open_case({"folder": str(tmp_path / "case"), "examiner": "Det. T", "case_number": "VAL-1"})
    return app, tmp_path, [str(k) for k in known]


def _run(app, **kw):
    name = app.start_validation(kw)
    while app.job["running"]:
        time.sleep(0.05)
    assert app.job["error"] is None, app.job["error"]
    return name, json.loads((app._validation_dir() / name / "validation.json").read_text())


def test_pass_and_mark_validated(lab):
    app, t, known = lab
    name, r = _run(app, signature_id="asf-wmv", known_files=known, test_image=str(t / "usb.img"),
                   negative_image=str(t / "clean.img"))
    assert r["verdict"] == "PASS", r["failures"]
    assert all(k["status"] == "recovered" for k in r["known_files"])
    assert r["negative"]["items"] == 0
    assert "PASS" in (app._validation_dir() / name / "validation_report.html").read_text()
    sig = app.mark_validated(name)
    assert sig["validated"] is True and sig["validation"]["known_files"] == 3
    assert sig["validation"]["dfx_version"] == r["tool"]["version"]
    assert "marked VALIDATED" in (t / "case" / "case_log.txt").read_text()


def test_missing_known_file_fails_and_cannot_be_marked(lab):
    app, t, known = lab
    extra = str(_asf(t / "not_on_usb.asf", 5))
    name, r = _run(app, signature_id="asf-wmv", known_files=known + [extra], test_image=str(t / "usb.img"))
    assert r["verdict"] == "FAIL" and any("not_on_usb.asf: not found" in f for f in r["failures"])
    with pytest.raises(ValueError, match="only a PASS"):
        app.mark_validated(name)


def test_unexpected_items_fail_unless_allowed(lab):
    app, t, known = lab
    _, r = _run(app, signature_id="asf-wmv", known_files=known[:2], test_image=str(t / "usb.img"))
    assert r["verdict"] == "FAIL" and len(r["unexpected"]) == 1
    _, r2 = _run(app, signature_id="asf-wmv", known_files=known[:2], test_image=str(t / "usb.img"), allow_other=True)
    assert r2["verdict"] == "PASS" and len(r2["unexpected"]) == 1


def test_wrong_length_is_diagnosed(lab):
    app, t, known = lab
    data = open(known[2], "rb").read()
    img = t / "cut.img"
    img.write_bytes(os.urandom(5000) + data[: len(data) // 2] + os.urandom(9000))   # truncated copy only
    _, r = _run(app, signature_id="asf-wmv", known_files=[known[2]], test_image=str(img))
    assert r["verdict"] == "FAIL"
    assert r["known_files"][0]["status"] in ("wrong length", "not found")


def test_changed_signature_cannot_use_old_validation(lab):
    app, t, known = lab
    name, r = _run(app, signature_id="asf-wmv", known_files=known, test_image=str(t / "usb.img"))
    sig = dict(app.lib.get("asf-wmv"))
    sig["max_size"] = 12345678                         # behavior change after the test
    app.save_signature(sig)
    with pytest.raises(ValueError, match="changed after this validation"):
        app.mark_validated(name)


def test_editing_a_validated_signature_clears_validation(lab):
    app, t, known = lab
    name, _ = _run(app, signature_id="asf-wmv", known_files=known, test_image=str(t / "usb.img"))
    app.mark_validated(name)
    sig = dict(app.lib.get("asf-wmv"))
    sig["notes"] = "label change only"                  # labels don't change behavior: stays validated
    assert app.save_signature(sig)["validated"] is True
    sig["min_size"] = 999                               # behavior change: validation no longer applies
    s2 = app.save_signature(sig)
    assert s2["validated"] is False and s2["validation"] is None


def test_tampered_report_blocks_marking(lab):
    app, t, known = lab
    name, _ = _run(app, signature_id="asf-wmv", known_files=known, test_image=str(t / "usb.img"))
    rp = app._validation_dir() / name / "validation_report.html"
    rp.write_text(rp.read_text().replace("FAIL", "PASS") + "<!-- edited -->")
    with pytest.raises(ValueError, match="report was changed"):
        app.mark_validated(name)


def test_old_dfx_version_record_cannot_mark(lab):
    app, t, known = lab
    name, _ = _run(app, signature_id="asf-wmv", known_files=known, test_image=str(t / "usb.img"))
    p = app._validation_dir() / name / "validation.json"
    r = json.loads(p.read_text())
    r["tool"]["version"] = "2026.1.1"
    p.write_text(json.dumps(r))
    with pytest.raises(ValueError, match="run it again"):
        app.mark_validated(name)
