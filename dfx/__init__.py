"""DVR Forensic Extractor (DFX).

Reads DVR/NVR hard drives and exported clips, identifies the filesystem,
carves video by signature, rebuilds proprietary DVR streams and converts
them to MP4 with the original DVR timestamps preserved.

Copyright (c) 2026 Christopher A. Tankelewicz (ThinkTank4n6)
MIT License - see LICENSE.
"""
from pathlib import Path

_vf = Path(__file__).resolve().parent.parent / "VERSION"
try:
    __version__ = _vf.read_text(encoding="utf-8").strip()
except OSError:  # frozen build without VERSION next to it
    __version__ = "2026.11.6"

APP_NAME = "DVR Forensic Extractor"
APP_SHORT = "DFX"
DEFAULT_PORT = 8788
