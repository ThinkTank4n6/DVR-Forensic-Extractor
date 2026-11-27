# Changelog

## Version numbers
- **Official release: Year.Month.Release** (3 parts), numbered by the **year and month it is published** (as FME does). The first official release in a month is `.1`, the next `.2`. Example: published in December 2026 -> `v2026.12.1`.
- **Pre-release build: Year.Month.Release.Build** (4 parts). Builds count up after the last release line: `v2026.11.1.12`, `v2026.11.1.13`, ... After official `v2026.12.1`, the next builds are `v2026.12.1.1`, `v2026.12.1.2`, ...
- **Every new version must be higher than every version already published.** Compared part by part, a missing 4th part comes first: `2026.11.1 < 2026.11.1.12 < 2026.11.2 < 2026.12.1 < 2026.12.1.1`. So an official release published in the same month as its pre-release line takes the next number (November: `v2026.11.2`, not `v2026.11.1`).

The release workflow decides pre-release (4 parts) vs official (3 parts, marked Latest) from the tag, and refuses a tag that doesn't match `VERSION` or isn't higher than every existing tag.
Versions before v2026.11.1.12 used three parts for every build; they were all pre-releases.

All builds so far are early development builds, **not yet tested on real DVR evidence**.

## v2026.11.1.12 - Validate (first build with the new version numbers)
- Version scheme: pre-release builds are Year.Month.Release.Build; the release workflow publishes 4-part tags as pre-releases and 3-part tags as official releases (marked Latest), and refuses a tag that doesn't match VERSION. About and `doctor` say "pre-release build 12 of 2026.11.1".
- **Validate** (Signatures > Validate): known files + a test image (+ optional negative image) -> hashes everything, carves with only the signature under test, and records **PASS** only if every known file is recovered byte-for-byte, no unexpected items are found (unless the examiner states the media may hold others), the negative image yields nothing, and there were no read problems. Wrong-length recoveries are diagnosed. JSON record + HTML report in `<case>/validation/`.
- **Mark Validated** only from a PASS record, only for the exact signature definition tested (definition SHA-256), only with the same DFX version, and only if the report is unchanged (report SHA-256). The record is stored with the signature. Saving a behavior change from the editor clears it; label-only edits keep it.
- Carve reports show each signature's validation date, flag signatures validated with an older DFX version ("re-validate"), and mark validations entered by hand without a DFX record.
- Fixed: two runs or validations started in the same second collided on folder name (the second crashed).
- Fixed: jobs that finished between two status polls (under a second) never refreshed the page.
- Learner: the "standard format" message names the right length method (ASF object walk vs mediacarve) and isn't shown twice; it suggests validating the built-in signature with the same files.

## v2026.11.10 - Dahua .asf exports
- **Found with the examiner's Dahua .asf exports:** the learner reported "no length field or footer" and a failed self-test. ASF records its size at byte 70 (past the learner's 64-byte search), has no frame marker at byte 0, and DFX's ASF signature only took a fixed size.
- New structural mode **asf_walk**: walks ASF top-level objects (header, data, simple index, index, media-object index, timecode index), stops at a second header (back-to-back exports stay separate and exact), cuts at a newer ASF header inside a declared length (overwritten, labeled capped), and reports the File Properties file size (match/mismatch), creation date and duration. Checked against ffmpeg-written ASF. The built-in ASF/WMV signature now uses it.
- Learner: recognizes standard MP4/AVI/MKV (via mediacarve) and ASF exports and says which built-in signature already recovers them; finds frame streams that start after a file header (up to 4 KB); searches 128 bytes for a whole-file length field; the self-test is honest when lengths can only be estimated ("found, length estimated" instead of "failed"); the self-test expects frames after a file header.

## v2026.11.9 - Build 2: signature learner and hex viewer
- **Signature learner** (Signatures > Learn from Samples): drafts a signature from 3+ samples - header (variable bytes become ??), frame marker, length field (any offset, 1/2/4/8 bytes, either byte order, with adjust), footer and the bytes after it, timestamp field (Dahua packed or Unix; must never go backwards inside a sample) and channel field (suggestion). Bytes inside a learned field are wildcarded so the header can't overfit small samples. Every finding states its evidence. The draft is self-tested by planting each sample in random data and carving it back; drafts are never marked validated. Learns the Dahua DHAV layout exactly from three exports.
- **Hex viewer** (Hex tab), read-only: evidence or any file, 1 KB pages, go to offset, find hex (with ??) or text (searches 2 GB per click), selection with integer and time interpretations, Use as Header / Length Field / Use as Footer, **Follow Length** (checks the length lands on the next header and walks frame to frame), Open in Editor, Add as Sample (evidence ranges for the learner). **View in Hex** on the Results tab.
- **Windows Open dialog** for Image File, the case folder and learner samples (runs in a child process; the built-in browser is the fallback).
- Messages that must stay visible now use a pop-up note instead of the status bar.

## v2026.11.8 - no more scrolling for the log box
- The case log panel is hidden by default. The status bar shows the latest log line; **Log ▲** (or clicking the line) opens it; drag its top edge to resize; open/closed and height are remembered.
- Short windows (under 640 px tall, for example 150% display scaling) get a compact one-row ribbon. Checked at the examiner's window size (about 1274 × 466): no page scrolling on any tab.
- Home tab no longer says E01 needs libewf-python (built in since v2026.11.5).
- GitHub: the Windows Release Build now runs the full test matrix first and publishes nothing if a test fails; tag pushes no longer run a second, separate test workflow.

## v2026.11.7 - vendored files stay byte-identical on Windows
- **Found by GitHub's Windows test run:** Git for Windows (`core.autocrlf`) checked out `ewfprobe.py` and `mediacarve.py` with CRLF line endings, so their SHA-256 no longer matched `vendored.json` and the byte-identical test failed (correctly). The release build would have bundled the converted copies.
- New `.gitattributes`: `dfx/vendor/** -text`, so Git never converts the vendored files. Verified with a real `core.autocrlf=true` clone: README converts to CRLF, the vendored files stay byte-identical; without the file, both fail.
- `doctor` and the test now say *why* a vendored file differs (for example "line endings were converted to CRLF").

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
