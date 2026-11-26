"""Signature learner: each format kind it should learn, and the warnings it must give."""
import os
import random
import subprocess

import pytest

from dfx.carve.signatures import check
from dfx.learn import learn, sample_from_bytes, sample_from_file
from tests.fixtures import dhav_chain, ffmpeg_ok


def test_learns_dahua_style_frames_exactly():
    s = [sample_from_bytes(f"ch{c}.dav", dhav_chain(30 + c * 5, c, start_sec=c * 7)) for c in (1, 2, 5)]
    r = learn(s)
    sig = r["signature"]
    assert sig["mode"] == "frame_chain" and sig["header"] == "44 48 41 56"
    assert sig["length_field"] == {"offset": 12, "size": 4, "endian": "little", "adjust": 0, "multiplier": 1}
    assert (sig["footer"], sig["footer_tail"]) == ("64 68 61 76", 4)
    assert sig["timestamp_field"]["offset"] == 16 and sig["timestamp_field"]["format"] == "dahua_packed"
    assert sig["channel_field"] == {"offset": 6, "size": 1}
    assert r["self_test"]["passed"] and not check(sig) and sig["validated"] is False


def test_out_of_order_recordings_still_give_timestamp():
    s = [sample_from_bytes(f"c{c}.dav", dhav_chain(30, c, start_sec=60 - c * 20)) for c in (1, 2, 3)]
    assert learn(s)["signature"]["timestamp_field"]["offset"] == 16


def _be_frames(n, rnd):
    """A different made-up DVR: 'NVRF', big-endian payload length at 8 (excludes the 16-byte header)."""
    out = bytearray()
    for i in range(n):
        payload = rnd.randbytes(200 + rnd.randrange(300))
        out += b"NVRF" + bytes([rnd.randrange(2), 0, 0, 0]) + len(payload).to_bytes(4, "big") + i.to_bytes(4, "big")
        out += payload
    return bytes(out)


def test_learns_big_endian_length_with_adjust():
    rnd = random.Random(3)
    r = learn([sample_from_bytes(f"s{i}.bin", _be_frames(20, rnd)) for i in range(3)])
    sig = r["signature"]
    assert sig["mode"] == "frame_chain"
    assert sig["length_field"]["offset"] == 8 and sig["length_field"]["endian"] == "big"
    assert sig["length_field"]["adjust"] == 16 and r["self_test"]["passed"]


@pytest.mark.skipif(not ffmpeg_ok(), reason="ffmpeg not installed")
def test_learns_riff_avi_file_length(tmp_path):
    files = []
    for i, dur in enumerate((1, 2, 3)):
        p = tmp_path / f"clip{i}.avi"
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i",
                        f"testsrc=size=96x64:rate=5:duration={dur}", "-c:v", "mjpeg", str(p)], check=True)
        files.append(sample_from_file(str(p)))
    r = learn(files)
    sig = r["signature"]
    assert sig["mode"] == "header_length" and sig["header"].startswith("52 49 46 46 ?? ?? ?? ?? 41 56 49 20")
    assert sig["length_field"]["offset"] == 4 and sig["length_field"]["adjust"] == 8
    assert sig["extension"] == "avi" and r["self_test"]["passed"]


def test_learns_header_and_footer():
    rnd = random.Random(5)
    s = [sample_from_bytes(f"x{i}.cam", b"CAMv1\x00" + rnd.randbytes(500 + i * 77) + b"ENDCAM" + b"\x01\x02")
         for i in range(3)]
    sig = learn(s)["signature"]
    assert sig["mode"] == "header_footer" and sig["header"].startswith("43 41 4D 76 31 00")
    assert sig["footer"] in ("44 43 41 4D", "41 4D") or "4D" in sig["footer"]


def test_one_sample_warns():
    r = learn([sample_from_bytes("one.dav", dhav_chain(20, 1))])
    assert any("Only 1 sample" in w for w in r["warnings"])


def test_unrelated_samples_are_refused():
    with pytest.raises(ValueError, match="common first bytes"):
        learn([sample_from_bytes("a", b"\x00\x01" + os.urandom(100)), sample_from_bytes("b", b"\xff\xfe" + os.urandom(100))])


def test_failed_self_test_is_reported():
    # frames whose 'length' is wrong in half the frames: no length field may be claimed
    rnd = random.Random(9)
    bad = []
    for k in range(3):
        out = bytearray()
        for i in range(20):
            p = rnd.randbytes(100 + rnd.randrange(50))
            ln = len(p) + 8 if i % 2 else rnd.randrange(1 << 30)
            out += b"BADF" + ln.to_bytes(4, "little") + p
        bad.append(sample_from_bytes(f"b{k}", bytes(out)))
    r = learn(bad)
    assert r["signature"]["mode"] != "frame_chain"
    assert any("no length field explains" in w for w in r["warnings"])
