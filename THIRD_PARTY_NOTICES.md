# Licenses and notices

## This program

DVR Forensic Extractor (DFX) is released under the **MIT License**,
Copyright (c) 2026 Christopher A. Tankelewicz (ThinkTank4n6). The full text is
in `LICENSE`. It covers the code written for this project. Everything below is
somebody else's work, included under its own license, and keeps that license.

## Code included in this program's source

Kept byte-identical to what its author published, with its license beside it
in `dfx/vendor/` and its provenance (version, upstream, SHA-256) in
`dfx/vendor/vendored.json`. `python -m dfx doctor` and `tests/test_vendor_judge.py`
check every file against that SHA-256. These files are never edited here: fixes
go upstream and the file is re-vendored.

| component | version | what DFX uses it for | copyright | license |
|---|---|---|---|---|
| **mediacarve** (`dfx/vendor/mediacarve.py`) | 0.14.1 | Length judge for MP4/MOV, AVI and MKV/WebM (`dfx/carve/judge.py`) | Copyright (c) 2026 Alexis Brignoni | MIT (`dfx/vendor/LICENSE-mediacarve`) |
| **ewfprobe** (`dfx/vendor/ewfprobe.py`) | 0.17.3 | Reading E01/Ex01, AFF, VHD/VHDX, VMDK, QCOW and DMG images, and their stored acquisition hashes (`dfx/source.py`) | Copyright (c) 2026 Alexis Brignoni | MIT (`dfx/vendor/LICENSE-ewfprobe`) |

Both were received from Forensic Media Extractor's `fme/vendor/` folder, which
took them from GLEAPP 2026.5.8 and from the author's release archives; the
SHA-256 values match those FME records.

## Adapted code

| where | from | copyright | license |
|---|---|---|---|
| `tests/ewfwriter.py` (test-only E01 writer) | GLEAPP `tests/ewfwriter.py`, via Forensic Media Extractor | Copyright (c) 2026 charpy4n6, Alexis Brignoni | MIT (`dfx/vendor/LICENSE-gleapp`) |
| `dfx/carve/judge.py` (the judging rules) | Forensic Media Extractor `fme/engines/carve_judge.py` | Copyright (c) 2026 Christopher A. Tankelewicz | MIT |

## Acknowledgments

With thanks to **Alexis Brignoni** for mediacarve and ewfprobe, and to the
GLEAPP project (charpy4n6, Alexis Brignoni).

## No warranty

This program and the components above are provided "as is", without warranty
of any kind. DFX is a tool for an examiner; it does not replace the examiner's
own verification of what it reports.
