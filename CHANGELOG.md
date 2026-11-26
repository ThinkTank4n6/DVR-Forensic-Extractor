# Changelog

All versions are early development builds, **not yet tested on real DVR evidence**.

## v2026.11.6 - Windows file locking
- **Found on the examiner's Windows workstation:** a saved clock measurement was lost (39 of 40) because Windows briefly locks a freshly written file (Defender, Search indexer) and `os.replace` failed with "Access is denied". The same call saves the carve checkpoint every 15 s, so a long scan could crash the same way.
- New `dfx/fsutil.replace_retry`: retries a transient Windows lock with backoff (up to ~3 s). Used for the DVR records file, the checkpoint, carved-file renames and crash recovery. A checkpoint that still can't be saved is logged and retried at the next one; the scan continues. Temp files are cleaned up on failure.
- Tests simulate Windows locking so Linux CI covers it (verified to fail without the fix).
- Daylight-saving tests no longer skip on Windows (they used `time.tzset`, which Windows lacks).
- GitHub test matrix adds Python 3.15 (the workstation's version).

## v2026.11.5
- **E01 support built in.** Vendored Alexis Brignoni's ewfprobe 0.17.3 (MIT, byte-identical). E01/Ex01, AFF, VHD/VHDX, VMDK, QCOW and DMG images open without libewf. Opening a later segment (.E02...) says to open the .E01.
- **Stored acquisition hash check.** Hash Evidence compares DFX's MD5 (and SHA-1, when stored) with the hash recorded inside the E01, logs the result and prints it on the report.
- **mediacarve length judge.** Vendored mediacarve 0.14.1 (MIT, byte-identical). The built-in MP4/MOV, AVI and MKV/WebM signatures now take their length from mediacarve's structure walk. Every item records how its length was known: header, parsed or capped (new "Length is" column, CSV `bounded` column).
- **Overwritten recordings.** A video whose declared length contains another valid video header is cut there and labeled capped ("probably overwritten"), so the newer recording is never hidden.
- **False positive removed.** Random `ftyp` bytes in unallocated space were carved as huge "truncated" MP4s (one per ~512 MB of random data). The ftyp box must now be plausible.
- MKV is no longer a fixed-size guess: its length is parsed.
- `doctor` checks the vendored files' SHA-256; the release workflow runs `DFX.exe doctor` so a broken bundle fails the build.
- Runs from older versions can't be resumed (clear message); start a new scan.
- THIRD_PARTY_NOTICES.md added.

## v2026.11.4 - code-review fixes
- Max-size signatures no longer hide following files of the same type; an estimated end stops at the next header.
- Crash-safe, idempotent resume (no duplicates; `.part` files; original options kept; statistics restored).
- Evidence and case are locked while a job runs; hashes are tied to their source path; reports use a snapshot.
- Overlapping header candidates are all checked. Short reads are completed; read problems are reported.
- DVR records file is locked against parallel writes. Test on File is capped at 2 GB.
- Report flags unhashed evidence, read problems and incomplete scans. Cancel Job on Home. Clear port-in-use message.

## v2026.11.3
- Clock Offset tab: DVR clock measurement, drift, DST handling, conversions, worksheet; corrected times in carve reports.

## v2026.11.2
- Built-in User Manual on the ribbon.

## v2026.11.1
- Build 1: carving engine, signature library and editor, ribbon GUI, reports, checkpoint/resume.
