"""Windows briefly locks fresh files (Defender, Search indexer). Simulated here so
Linux CI covers it too. Found on the examiner's Windows workstation, v2026.11.5."""
import os
import threading

import pytest

import dfx.fsutil as fsutil
from dfx.carve import Carver, CarveOptions, SignatureLibrary
from dfx.clock import DvrStore
from dfx.source import open_source
from tests.fixtures import build_image


@pytest.fixture
def flaky_replace(monkeypatch):
    """os.replace fails like Windows on every other call (a scanner holding the file)."""
    real = os.replace
    lock, state = threading.Lock(), {"n": 0, "fails": 0}

    def replace(src, dst):
        with lock:
            state["n"] += 1
            fail = state["n"] % 2 == 1
            if fail:
                state["fails"] += 1
        if fail:
            raise PermissionError(5, "Access is denied", str(dst))
        return real(src, dst)
    monkeypatch.setattr(fsutil.os, "replace", replace)
    return state


def test_dvrstore_survives_windows_locking(tmp_path, flaky_replace):
    d = DvrStore(tmp_path).save_dvr({"name": "NVR"})

    def add(i):
        DvrStore(tmp_path).add_measurement(d["id"], {"dvr_time": f"2026-11-26 08:{i % 60:02d}:00",
                                                     "reference_time": "2026-11-26 08:00:00"})
    ts = [threading.Thread(target=add, args=(i,)) for i in range(40)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(DvrStore(tmp_path).get(d["id"])["measurements"]) == 40
    assert flaky_replace["fails"] >= 20
    assert not list(tmp_path.glob("*.tmp"))


def test_carve_survives_windows_locking(tmp_path, flaky_replace):
    img = build_image(tmp_path / "img")["image"]
    sigs = SignatureLibrary(tmp_path / "u").all()
    for s in sigs:
        s["enabled"] = True
    with open_source(str(img)) as src:
        c = Carver(src, sigs, CarveOptions(out_dir=str(tmp_path / "o"), chunk_size=4096, checkpoint_every=0))
        st = c.run()
    assert st.items == 3 and all((tmp_path / "o" / i.file).exists() for i in c.items)
    assert not list((tmp_path / "o").rglob("*.part"))


def test_permanent_error_is_not_retried_forever(tmp_path, monkeypatch):
    calls = {"n": 0}

    def never(src, dst):
        calls["n"] += 1
        raise PermissionError(5, "Access is denied")
    monkeypatch.setattr(fsutil.os, "replace", never)
    with pytest.raises(PermissionError):
        fsutil.replace_retry(tmp_path / "a", tmp_path / "b", timeout=0.2)
    assert 2 < calls["n"] < 50


def test_non_transient_error_raises_immediately(tmp_path):
    with pytest.raises(FileNotFoundError):
        fsutil.replace_retry(tmp_path / "missing", tmp_path / "b")


def test_checkpoint_failure_does_not_crash_scan(tmp_path, monkeypatch):
    real, logs = os.replace, []

    def replace(src, dst):
        if str(dst).endswith("checkpoint.json") and not getattr(replace, "final", False):
            raise PermissionError(5, "Access is denied")
        return real(src, dst)
    monkeypatch.setattr(fsutil.os, "replace", replace)
    monkeypatch.setattr(fsutil.time, "sleep", lambda s: None)
    img = build_image(tmp_path / "img")["image"]
    sigs = [SignatureLibrary(tmp_path / "u").get("avi-riff")]
    with open_source(str(img)) as src:
        c = Carver(src, sigs, CarveOptions(out_dir=str(tmp_path / "o"), chunk_size=4096, checkpoint_every=0),
                   log=logs.append)
        orig = c._write_checkpoint

        def ck(pos, final=False):
            replace.final = final
            return orig(pos, final)
        c._write_checkpoint = ck
        st = c.run()
    assert st.items == 1 and any("checkpoint not saved" in m for m in logs)
