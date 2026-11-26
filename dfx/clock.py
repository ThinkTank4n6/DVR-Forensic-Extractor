"""DVR clock offset: measurements, drift, DST check and time conversion.

Terms
  DVR time     the time the recorder displays / writes (its own clock)
  Actual time  the true local time from a trusted reference clock
  Offset       DVR time - Actual time   (positive = DVR is fast / ahead)

  Actual = DVR - offset          DVR = Actual + offset

With one measurement the offset is assumed constant. With two or more, a
drift rate (seconds per day) is fitted and the offset is estimated for the
moment being converted. Every conversion says which measurements it used and
whether it had to extrapolate outside the measured period.

All times are naive local wall-clock times ("YYYY-MM-DD HH:MM:SS"), as shown
on the recorder and on the reference clock. The DST check uses the
workstation's time zone.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from .fsutil import replace_retry

FMT = "%Y-%m-%d %H:%M:%S"


class ClockError(ValueError):
    pass


# ---------------------------------------------------------------- parsing
def parse_time(text: str) -> _dt.datetime:
    """Accepts 'YYYY-MM-DD HH:MM:SS', 'YYYY-MM-DDTHH:MM:SS', 'MM/DD/YYYY HH:MM:SS [AM|PM]'."""
    t = (text or "").strip().replace("T", " ")
    if not t:
        raise ClockError("time is empty")
    t = re.sub(r"\.\d+$", "", t).upper()
    t = re.sub(r"\s+", " ", t)
    for f in (FMT, "%Y-%m-%d %H:%M", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
              "%m/%d/%Y %I:%M %p", "%m/%d/%Y %H:%M"):
        try:
            return _dt.datetime.strptime(t, f)
        except ValueError:
            continue
    raise ClockError(f"can't read time {text!r} - use YYYY-MM-DD HH:MM:SS")


def fmt(d: _dt.datetime) -> str:
    return d.strftime(FMT)


def fmt12(d: _dt.datetime) -> str:
    return d.strftime("%m/%d/%Y %I:%M:%S %p")


def describe_offset(seconds: float) -> str:
    """'DVR is 1 h 04 min 12 s fast (ahead of actual time)'."""
    s = round(seconds)
    if s == 0:
        return "Time is exact"
    a = abs(s)
    d, rem = divmod(a, 86400)
    h, rem = divmod(rem, 3600)
    m, sec = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d} d")
    if h:
        parts.append(f"{h} h")
    if m:
        parts.append(f"{m} min")
    if sec or not parts:
        parts.append(f"{sec} s")
    word = "fast (ahead of actual time)" if s > 0 else "slow (behind actual time)"
    return f"DVR is {' '.join(parts)} {word}"


def signed_hms(seconds: float) -> str:
    s = round(seconds)
    sign = "+" if s >= 0 else "-"
    a = abs(s)
    return f"{sign}{a // 3600:02d}:{a % 3600 // 60:02d}:{a % 60:02d}"


# ---------------------------------------------------------------- DST / zone
def local_utc_offset(d: _dt.datetime) -> int:
    """Seconds east of UTC for a naive local time, using the workstation's zone."""
    ts = time.mktime(d.timetuple())
    return time.localtime(ts).tm_gmtoff


def dst_warning(a: _dt.datetime, b: _dt.datetime) -> str:
    oa, ob = local_utc_offset(a), local_utc_offset(b)
    if oa == ob:
        return ""
    return (f"A daylight-saving change falls between {fmt(a)} and {fmt(b)} "
            f"(UTC{oa / 3600:+g} vs UTC{ob / 3600:+g} on this workstation). If the recorder does "
            "not adjust for DST automatically, the offset at the incident differs by "
            f"{abs(oa - ob) / 3600:g} hour from the measured offset. Check the recorder's DST setting.")


def reference_clock_status() -> dict:
    """What the workstation clock is synced to (Windows Time service)."""
    out = {"zone": time.strftime("%Z"), "utc_offset_hours": -time.timezone / 3600}
    if sys.platform.startswith("win"):
        try:
            r = subprocess.run(["w32tm", "/query", "/status"], capture_output=True, text=True, timeout=5)
            txt = r.stdout.strip()
            out["w32tm"] = txt
            for line in txt.splitlines():
                k, _, v = line.partition(":")
                k = k.strip().lower()
                if k == "source":
                    out["sync_source"] = v.strip()
                elif k.startswith("last successful sync time"):
                    out["last_sync"] = v.strip()
        except (OSError, subprocess.SubprocessError) as e:
            out["w32tm_error"] = str(e)
    return out


# ---------------------------------------------------------------- model
def offset_of(m: dict) -> float:
    return (parse_time(m["dvr_time"]) - parse_time(m["reference_time"])).total_seconds()


def drift_fit(measurements: list[dict]) -> dict | None:
    """Least-squares line offset = a + b * t  (t in days on the reference clock)."""
    pts = sorted(((parse_time(m["reference_time"]), offset_of(m)) for m in measurements), key=lambda p: p[0])
    if len(pts) < 2:
        return None
    t0 = pts[0][0]
    xs = [(p[0] - t0).total_seconds() / 86400 for p in pts]
    ys = [p[1] for p in pts]
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None  # all at the same moment
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    resid = max(abs(y - (a + b * x)) for x, y in zip(xs, ys))
    return {"t0": fmt(t0), "intercept_s": a, "rate_s_per_day": b, "max_residual_s": resid,
            "first": fmt(pts[0][0]), "last": fmt(pts[-1][0]), "points": n}


def offset_at(dvr: dict, actual: _dt.datetime, use_drift: bool = True) -> dict:
    """Estimated offset at an actual (reference-clock) moment."""
    ms = dvr.get("measurements") or []
    if not ms:
        raise ClockError("this DVR has no offset measurements yet")
    fit = drift_fit(ms) if use_drift else None
    notes = []
    if fit:
        x = (actual - parse_time(fit["t0"])).total_seconds() / 86400
        off = fit["intercept_s"] + fit["rate_s_per_day"] * x
        method = (f"drift fit over {fit['points']} measurements "
                  f"({fit['rate_s_per_day']:+.2f} s/day)")
        if actual < parse_time(fit["first"]) or actual > parse_time(fit["last"]):
            notes.append("Outside the measured period: the drift was extrapolated.")
        used = [m["id"] for m in ms]
    else:
        # nearest measurement in time
        m = min(ms, key=lambda m: abs((parse_time(m["reference_time"]) - actual).total_seconds()))
        off = offset_of(m)
        method = "single measurement (offset assumed constant)" if len(ms) == 1 else \
                 f"nearest measurement {m['reference_time']} (offset assumed constant)"
        used = [m["id"]]
        if len(ms) == 1:
            notes.append("Only one measurement: any drift between the incident and the measurement "
                          "is not accounted for. Take a second measurement days later to measure drift.")
    near = min(ms, key=lambda m: abs((parse_time(m["reference_time"]) - actual).total_seconds()))
    mt = parse_time(near["reference_time"])
    shift = local_utc_offset(actual) - local_utc_offset(mt)
    setting = (dvr.get("dst_setting") or "").strip().lower()
    if shift:
        if setting == "auto dst off":
            # recorder keeps one fixed clock; local time moved by `shift` but the DVR did not
            off -= shift
            method += f"; DST adjusted {-shift / 3600:+g} h (recorder does not apply DST)"
            notes.append(f"Daylight-saving change between {fmt(actual)} and {fmt(mt)}: the recorder is recorded "
                         f"as NOT adjusting for DST, so the offset was changed by {-shift / 3600:+g} hour for this time.")
        elif setting == "auto dst on":
            notes.append(f"Daylight-saving change between {fmt(actual)} and {fmt(mt)}: the recorder is recorded as "
                         "adjusting for DST automatically, so no hour correction was applied. Confirm the recorder "
                         "actually changed its clock on the DST date.")
        else:
            notes.append(dst_warning(actual, mt) + " Record the recorder's DST setting on the DVR to have DFX "
                         "apply or skip the hour automatically.")
    return {"offset_s": off, "method": method, "measurements_used": used, "notes": notes}


def convert(dvr: dict, when: str, direction: str, use_drift: bool = True) -> dict:
    """direction: 'dvr_to_actual' or 'actual_to_dvr'."""
    t = parse_time(when)
    if direction == "actual_to_dvr":
        est = offset_at(dvr, t, use_drift)
        out = t + _dt.timedelta(seconds=round(est["offset_s"]))
        actual, dvr_t = t, out
    elif direction == "dvr_to_actual":
        # offset depends on actual time; iterate (converges in 1-2 steps)
        guess = t - _dt.timedelta(seconds=round(offset_of(dvr["measurements"][-1]))) if dvr.get("measurements") else t
        for _ in range(4):
            est = offset_at(dvr, guess, use_drift)
            nxt = t - _dt.timedelta(seconds=round(est["offset_s"]))
            if nxt == guess:
                break
            guess = nxt
        actual, dvr_t = guess, t
    else:
        raise ClockError("direction must be dvr_to_actual or actual_to_dvr")
    return {"direction": direction, "input": fmt(t), "dvr_time": fmt(dvr_t), "actual_time": fmt(actual),
            "offset_s": round(est["offset_s"], 2), "offset_hms": signed_hms(est["offset_s"]),
            "offset_text": describe_offset(est["offset_s"]), "method": est["method"],
            "measurements_used": est["measurements_used"], "notes": est["notes"]}


# ---------------------------------------------------------------- storage
def _utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path.resolve()))
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.RLock())


def _locked(fn):
    def wrap(self, *a, **kw):
        with self._lock:
            return fn(self, *a, **kw)
    wrap.__name__, wrap.__doc__ = fn.__name__, fn.__doc__
    return wrap


class DvrStore:
    """<case>/dvrs.json - recorders and their clock measurements.

    Every read-modify-write holds a per-file lock: the GUI server handles
    requests on parallel threads.
    """

    def __init__(self, case_folder: str | Path):
        self.path = Path(case_folder) / "dvrs.json"
        self._lock = _lock_for(self.path)

    @_locked
    def all(self) -> list[dict]:
        if not self.path.exists():
            return []
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, items):
        tmp = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        tmp.write_text(json.dumps(items, indent=2), encoding="utf-8")
        try:
            replace_retry(tmp, self.path)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise

    @_locked
    def get(self, dvr_id: str) -> dict:
        for d in self.all():
            if d["id"] == dvr_id:
                return d
        raise ClockError(f"DVR {dvr_id} not found")

    @_locked
    def save_dvr(self, data: dict) -> dict:
        items = self.all()
        name = (data.get("name") or "").strip()
        if not name:
            raise ClockError("give the DVR a name or location")
        fields = ("name", "location", "make", "model", "serial", "channels", "dst_setting", "notes")
        if data.get("id"):
            d = next((x for x in items if x["id"] == data["id"]), None)
            if not d:
                raise ClockError("DVR not found")
            for k in fields:
                if k in data:
                    d[k] = data[k]
            d["modified"] = _utc()
        else:
            d = {"id": uuid.uuid4().hex[:8], "created": _utc(), "measurements": [], "conversions": []}
            for k in fields:
                d[k] = data.get(k, "")
            items.append(d)
        self._save(items)
        return d

    @_locked
    def delete_dvr(self, dvr_id: str) -> bool:
        items = self.all()
        keep = [x for x in items if x["id"] != dvr_id]
        self._save(keep)
        return len(keep) != len(items)

    @_locked
    def add_measurement(self, dvr_id: str, m: dict, examiner: str = "") -> dict:
        items = self.all()
        d = next((x for x in items if x["id"] == dvr_id), None)
        if not d:
            raise ClockError("DVR not found")
        dvr_t, ref_t = parse_time(m.get("dvr_time", "")), parse_time(m.get("reference_time", ""))
        rec = {"id": uuid.uuid4().hex[:8], "dvr_time": fmt(dvr_t), "reference_time": fmt(ref_t),
               "offset_s": (dvr_t - ref_t).total_seconds(),
               "offset_text": describe_offset((dvr_t - ref_t).total_seconds()),
               "reference_source": (m.get("reference_source") or "").strip() or "Workstation clock",
               "reference_status": m.get("reference_status") or {},
               "method": (m.get("method") or "").strip(),
               "examiner": examiner, "notes": (m.get("notes") or "").strip(), "recorded": _utc()}
        d["measurements"].append(rec)
        self._save(items)
        return rec

    @_locked
    def delete_measurement(self, dvr_id: str, mid: str) -> bool:
        items = self.all()
        d = next((x for x in items if x["id"] == dvr_id), None)
        if not d:
            return False
        n = len(d["measurements"])
        d["measurements"] = [m for m in d["measurements"] if m["id"] != mid]
        self._save(items)
        return len(d["measurements"]) != n

    @_locked
    def log_conversion(self, dvr_id: str, result: dict, label: str = "") -> dict:
        items = self.all()
        d = next((x for x in items if x["id"] == dvr_id), None)
        if not d:
            raise ClockError("DVR not found")
        rec = dict(result, label=label.strip(), recorded=_utc())
        d.setdefault("conversions", []).append(rec)
        self._save(items)
        return rec

    def summary(self, d: dict) -> dict:
        s = dict(d)
        fit = drift_fit(d["measurements"]) if len(d["measurements"]) >= 2 else None
        s["drift"] = fit
        if d["measurements"]:
            last = d["measurements"][-1]
            s["current_offset_text"] = last["offset_text"]
            s["current_offset_s"] = last["offset_s"]
        return s
