# DVR Forensic Extractor (DFX)

**Version 2026.11.1 — Build 1: carving engine**

DFX reads DVR/NVR hard drives and drive images read-only and carves video using a signature library that you can edit. It is the first part of a DVR examination tool: the later builds add a signature learner, Dahua and Hikvision stream rebuilding, MP4 output with DVR timestamps, and drive filesystem parsing.

Copyright (c) 2026 Christopher A. Tankelewicz (ThinkTank4n6). MIT License, provided without warranty.

## What this build does

* **Evidence (always read-only)**
  * Raw, dd and img images
  * Split raw images (`.001`, `.002` …)
  * Windows physical drives (`\\.\PhysicalDriveN`): run as Administrator and use a write blocker
  * E01/Ex01 images, if `libewf-python` is installed
* **Evidence hashing**: MD5 and SHA-256, recorded in the case and the report.
* **Five carving modes**, all defined in signature JSON:

| Mode | How the item's end is found |
|---|---|
| `header_footer` | First or last footer within `max_size` |
| `header_length` | Size field in the header: offset, size, byte order, adjust, multiplier |
| `header_maxsize` | Fixed `max_size` bytes |
| `frame_chain` | Follows frame after frame using each frame's length field. Records the frame count, channels and first/last device time |
| `box_walk` | MP4/MOV/3GP: walks the top-level boxes and flags files that have no `moov` box |

* **Scanning**
  * 64 MB chunks that overlap, so a header split across two chunks is still found
  * Optional "sector-aligned only" setting
  * A start and end range
  * A maximum number of items
* **Checkpoint and resume** after a cancel, a crash or a reboot. Resume refuses to continue if the signatures changed since the checkpoint.
* **Dry run**: logs the items without copying them out.
* **Output**
  * One file per carved item, with MD5 and SHA-256
  * `carve_log.csv`
  * `carve_session.json`, which holds the exact signature definitions used and their SHA-256
  * `report.html`
* **Case log**: every action is written to `case_log.txt` with a UTC time.
* **GUI**: a ribbon interface (Home, Carve, Signatures, Results, Help) at `http://127.0.0.1:8788`. FME uses port 8787.
* **Signature editor**: create, copy or edit signatures, test them on a sample file, and import or export them as JSON. Imported signatures always start out unvalidated.

## Run

Requires Python 3.11 or later. No packages are required.

```
run_dfx.bat                     (right-click > Run as administrator for physical drives)
python -m dfx gui
python -m dfx carve E:\img\dvr.001 D:\cases\123\carve1 --sig dahua-dhav --dry-run
python -m dfx hash  E:\img\dvr.E01
python -m dfx sigs
python -m dfx drives
python -m dfx doctor
```

## Signature format

```json
{
  "id": "dahua-dhav",
  "name": "Dahua DHAV frame chain",
  "extension": "dav",
  "header": "44 48 41 56",
  "mode": "frame_chain",
  "length_field": {"offset": 12, "size": 4, "endian": "little", "adjust": 0, "multiplier": 1},
  "footer": "64 68 61 76",
  "footer_tail": 4,
  "max_size": 4294967296,
  "channel_field": {"offset": 6, "size": 1},
  "timestamp_field": {"offset": 16, "size": 4, "endian": "little", "format": "dahua_packed"},
  "validated": false
}
```

* `??` in a header matches any byte. Footers cannot contain wildcards.
* `header_offset` handles formats whose magic bytes aren't at the start of the file (MP4 `ftyp` is at offset 4).
* Timestamp formats: `unix`, `dahua_packed`, `filetime`. Device times are reported exactly as recorded, with no time-zone or clock-offset correction.
* User signatures are stored in `%APPDATA%\DFX\signatures`. A user signature with the same `id` as a built-in one replaces it.

## Validation status

Every built-in signature ships **unvalidated**, and the report says so.

* The Dahua DHAV offsets follow publicly documented parsers, but the channel offset is not confirmed.
* The Hikvision IMKH signature only takes a fixed size.

Before using DFX on casework:

1. Build test images with known contents.
2. Confirm that every planted item is found byte-for-byte.
3. Mark the signature validated.

The included tests (`python -m pytest`) do this on a synthetic drive image. The image contains MP4, AVI, a 40-frame DHAV chain, a broken chain and a custom header/footer pattern placed among random data. The tests check exact offsets, lengths and hashes, chunk-boundary handling, resume, dry run, and that the evidence hash is unchanged.

Measured speed on the build machine was about 220 MB/s with all signatures enabled. On spinning drives, disk speed will usually be the limit.

## Build an .exe

`build_windows.bat` (needs `pip install pyinstaller`). Pushing a `v*` tag runs the **Windows Release Build** workflow, which publishes `DFX-vX-windows.zip` and its `.sha256` file.

## Roadmap

1. ~~Carving engine and signature format~~ (this build)
2. Signature learner: common header and footer, repeating frame markers, length-field detection
3. Dahua stream layer: group frames by channel, sort by time, MP4 with a DVR-time subtitle track, frame map
4. Filesystem detection
5. Hikvision HIKBTREE parser, then the Dahua filesystem parser
