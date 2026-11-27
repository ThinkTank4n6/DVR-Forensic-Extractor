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
    __version__ = "2026.11.1.12"

# Version scheme
#   Year.Month.Release.Build  (4 parts)  pre-release build, e.g. 2026.11.1.12
#   Year.Month.Release        (3 parts)  official release,  e.g. 2026.11.2
# Pre-releases count up their 4th part until the next official release.
VERSION_TUPLE = tuple(int(x) for x in __version__.split("."))
IS_PRERELEASE = len(VERSION_TUPLE) == 4


def version_label() -> str:
    if IS_PRERELEASE:
        return f"{__version__} (pre-release build {VERSION_TUPLE[3]} of {'.'.join(map(str, VERSION_TUPLE[:3]))})"
    return f"{__version__} (official release)"


APP_NAME = "DVR Forensic Extractor"
APP_SHORT = "DFX"
DEFAULT_PORT = 8788
