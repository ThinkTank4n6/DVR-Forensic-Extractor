# DVR Forensic Extractor (DFX)

> [!WARNING]
> **New project — not yet tested on real DVR evidence.**
> This is an early development build. It has only been tested against synthetic test images, not against drives or exports from real DVR/NVR recorders. Every built-in signature is unvalidated, and the Dahua DHAV offsets are partly unconfirmed. **Do not use it for casework** or rely on its results until it has been validated against known test data from real recorders.

**Version 2026.11.1.12 (pre-release build 12) — Build 2: signature learner + hex viewer — Build 1 + E01 built in (ewfprobe) + mediacarve length judge**

The full User Manual is built into the program (ribbon → **User Manual**) and is also at [`dfx/web/manual.html`](dfx/web/manual.html).

DFX reads DVR/NVR hard drives and drive images read-only and carves video using a signature library that you can edit. It is the first part of a DVR examination tool: the later builds add a signature learner, Dahua and Hikvision stream rebuilding, MP4 output with DVR timestamps, and drive filesystem parsing.

Copyright (c) 2026 Christopher A. Tankelewicz (ThinkTank4n6). MIT License, provided without warranty.

## What this build does

* **Evidence (always read-only)**
  * Raw, dd and img images
  * Split raw images (`.001`, `.002` …)
  * Windows physical drives (`\\.\PhysicalDriveN`): run as Administrator and use a write blocker
  * E01/Ex01, AFF, VHD/VHDX, VMDK, QCOW and DMG images, built in through Alexis Brignoni's ewfprobe (no libewf needed). DFX's hash is checked against the acquisition hash stored in the E01.
* **Evidence hashing**: MD5 and SHA-256, recorded in the case and the report.
* **Length judge:** MP4/MOV, AVI and MKV/WebM lengths come from Alexis Brignoni's mediacarve, which walks each format's structure. Every item records how its length was known (header, parsed or capped), and a recording whose tail was overwritten is cut where the newer recording starts, so the newer one is never hidden.
* **Five carving modes**, all defined in signature JSON:

| Mode | How the item's end is found |
|---|---|
| `header_footer` | First or last footer within `max_size` |
| `header_length` | Size field in the header: offset, size, byte order, adjust, multiplier |
| `header_maxsize` | Fixed `max_size` bytes |
| `frame_chain` | Follows frame after frame using each frame's length field. Records the frame count, channels and first/last device time |
| `box_walk` | MP4/MOV/3GP: walks the top-level boxes and flags files that have no `moov` box |
| `asf_walk` | ASF/WMV (Dahua `.asf` exports): walks header, data and index objects; reports the header's file size, creation date and duration |

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
* **Clock Offset tab**:
  * Measures a recorder's clock against the workstation clock (recording its Windows Time sync source) or an external reference.
  * Converts DVR ↔ actual time, with drift fitted from two or more measurements and automatic daylight-saving handling based on the recorder's DST setting.
  * Logs each conversion and prints an offset worksheet.
  * Carve reports can show corrected actual times.
* **Signature learner (Build 2):** give it 3+ known-good samples (recorder exports, or byte ranges picked in the hex viewer). It finds the header, a repeating frame marker, the length field, the footer, a timestamp field and a channel field, writes a draft signature (never marked validated), and self-tests it by planting every sample in random data and carving it back.
* **Hex viewer (read-only):** browse evidence or any file, find hex/text, see what selected bytes mean (integers, Unix/Dahua/FILETIME times), build a signature by marking header, length field and footer, and **Follow Length** to check the length field lands on the next header. **View in Hex** from Results.
* **Windows Open dialog:** Image File, case folder and sample files use the normal Windows dialog (the built-in browser is the fallback).
* **Signature editor**: create, copy or edit signatures, test them on a sample file, and import or export them as JSON. Imported signatures always start out unvalidated.

## Run

Requires Python 3.11 or later. No packages are required. Third-party code included in the source is listed in `THIRD_PARTY_NOTICES.md`.

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

**Validate** (Signatures tab) proves a signature on known data: give it the known files (originals), a test image you prepared holding them, and optionally a negative image. DFX hashes everything, carves with only that signature, and records PASS only if every known file is recovered byte-for-byte, nothing unexpected is found, and the negative image yields nothing. A signature can be marked validated only from a PASS record, only for the exact definition tested, and only with the same DFX version; changing the signature later clears it.


Every built-in signature ships **unvalidated**, and the report says so.

* The Dahua DHAV offsets follow publicly documented parsers, but the channel offset is not confirmed.
* The Hikvision IMKH signature only takes a fixed size.

Before using DFX on casework:

1. Build test images with known contents.
2. Confirm that every planted item is found byte-for-byte.
3. Mark the signature validated.

The included tests (`python -m pytest`) do this on a synthetic drive image. The image contains MP4, AVI, a 40-frame DHAV chain, a broken chain and a custom header/footer pattern placed among random data. The tests check exact offsets, lengths and hashes, chunk-boundary handling, resume, dry run, and that the evidence hash is unchanged.

Measured speed on the build machine was about 220 MB/s with all signatures enabled. On spinning drives, disk speed will usually be the limit.

## Version numbers

Official releases are numbered by the year and month they are published: `Year.Month.Release` (for example `2026.12.1`). Pre-release builds add a build number: `Year.Month.Release.Build` (for example `2026.11.1.12`). Every new version is higher than every published one. See CHANGELOG.md.

## Build an .exe

`build_windows.bat` (needs `pip install pyinstaller`). Pushing a `v*` tag runs the **Windows Release Build** workflow, which publishes `DFX-vX-windows.zip` and its `.sha256` file.

## Roadmap

1. ~~Carving engine and signature format~~
2. ~~Signature learner and hex viewer~~ (this build)
3. Dahua stream layer: group frames by channel, sort by time, MP4 with a DVR-time subtitle track, frame map
4. Filesystem detection
5. Hikvision HIKBTREE parser, then the Dahua filesystem parser
