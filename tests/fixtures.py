"""Builds a synthetic 'DVR drive' image with known contents at known offsets."""
from __future__ import annotations

import os
import random
import shutil
import subprocess
from pathlib import Path


def ffmpeg_ok() -> bool:
    return shutil.which("ffmpeg") is not None


def make_mp4(path: Path):
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i",
                    "testsrc=size=160x120:rate=10:duration=2", "-c:v", "libx264",
                    "-pix_fmt", "yuv420p", str(path)], check=True)


def make_avi(path: Path):
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i",
                    "testsrc=size=160x120:rate=10:duration=2", "-c:v", "mjpeg",
                    str(path)], check=True)


def dahua_packed(y, mo, d, h, mi, s) -> int:
    return ((y - 2000) << 26) | (mo << 22) | (d << 17) | (h << 12) | (mi << 6) | s


def dhav_frame(n: int, channel: int, ts: int, payload: bytes) -> bytes:
    total = 24 + len(payload) + 8
    hdr = bytearray(24)
    hdr[0:4] = b"DHAV"
    hdr[4] = 0xFD if n % 10 == 0 else 0xFC
    hdr[6] = channel
    hdr[8:12] = n.to_bytes(4, "little")
    hdr[12:16] = total.to_bytes(4, "little")
    hdr[16:20] = ts.to_bytes(4, "little")
    return bytes(hdr) + payload + b"dhav" + total.to_bytes(4, "little")


def dhav_chain(count: int, channel: int, start_sec: int = 0) -> bytes:
    out = bytearray()
    rnd = random.Random(channel)
    for i in range(count):
        s = start_sec + i // 10
        ts = dahua_packed(2026, 11, 25, 14, (s // 60) % 60, s % 60)
        out += dhav_frame(i, channel, ts, bytes(rnd.getrandbits(8) for _ in range(300 + i % 50)))
    return bytes(out)


def build_image(dirpath: Path) -> dict:
    """Return {'image': path, 'truth': [...]}  (truth = expected items)."""
    dirpath.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(1234)
    noise = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))  # noqa: E731
    truth = []
    img = bytearray(noise(4096 * 3 + 17))

    if ffmpeg_ok():
        mp4 = dirpath / "src.mp4"
        avi = dirpath / "src.avi"
        make_mp4(mp4)
        make_avi(avi)
        for p, sig in ((mp4, "mp4-iso"), (avi, "avi-riff")):
            data = p.read_bytes()
            off = len(img)
            img += data
            truth.append({"sig": sig, "start": off, "length": len(data)})
            img += noise(5000 + rnd.randrange(3000))

    # Dahua chain 1: channel 2, 40 frames, then noise
    c1 = dhav_chain(40, 2)
    off = len(img)
    img += c1
    truth.append({"sig": "dahua-dhav", "start": off, "length": len(c1), "frames": 40,
                  "first_time": "2026-11-25 14:00:00", "last_time": "2026-11-25 14:00:03"})
    img += noise(777)

    # Header/footer test pattern ("CAMSTART ... CAMEND!")
    hf = b"CAMSTART" + noise(1000) + b"CAMEND!"
    off = len(img)
    img += hf
    truth.append({"sig": "test-hf", "start": off, "length": len(hf)})
    img += noise(4096)

    path = dirpath / "dvr_test.img"
    path.write_bytes(bytes(img))
    return {"image": path, "truth": truth, "size": len(img)}
