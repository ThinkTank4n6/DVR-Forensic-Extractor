import datetime as dt
import os
import time

import pytest

from dfx.clock import local_utc_offset as _REAL_LOCAL_UTC_OFFSET
from dfx.clock import (ClockError, DvrStore, convert, describe_offset, drift_fit, dst_warning,
                       parse_time, signed_hms)


def _us_eastern_offset(d: dt.datetime) -> int:
    """US Eastern UTC offset in seconds (2007+ rules: 2nd Sunday of March to 1st Sunday of November)."""
    def nth_sunday(year, month, n):
        first = dt.date(year, month, 1)
        return first + dt.timedelta(days=(6 - first.weekday()) % 7 + 7 * (n - 1))
    start = dt.datetime.combine(nth_sunday(d.year, 3, 2), dt.time(2))
    end = dt.datetime.combine(nth_sunday(d.year, 11, 1), dt.time(2))
    return -4 * 3600 if start <= d < end else -5 * 3600


@pytest.fixture(autouse=True)
def eastern(monkeypatch):
    """Pin the workstation zone to US Eastern on every OS (Windows has no time.tzset)."""
    import dfx.clock as clock
    monkeypatch.setattr(clock, "local_utc_offset", _us_eastern_offset)


def store(tmp_path, *measurements):
    s = DvrStore(tmp_path)
    d = s.save_dvr({"name": "Corner store NVR", "make": "Dahua"})
    for dvr_t, ref_t in measurements:
        s.add_measurement(d["id"], {"dvr_time": dvr_t, "reference_time": ref_t,
                                    "reference_source": "time.gov"}, "Det. T")
    return s, s.get(d["id"])


def test_parse_formats():
    assert parse_time("11/26/2026 08:48:17 AM") == dt.datetime(2026, 11, 26, 8, 48, 17)
    assert parse_time("11/26/2026 8:48:17 pm") == dt.datetime(2026, 11, 26, 20, 48, 17)
    assert parse_time("2026-11-26T08:48:17") == dt.datetime(2026, 11, 26, 8, 48, 17)
    with pytest.raises(ClockError):
        parse_time("yesterday")


def test_describe():
    assert describe_offset(0) == "Time is exact"
    assert describe_offset(252) == "DVR is 4 min 12 s fast (ahead of actual time)"
    assert describe_offset(-3725) == "DVR is 1 h 2 min 5 s slow (behind actual time)"
    assert signed_hms(-3725) == "-01:02:05"


def test_single_measurement_both_directions(tmp_path):
    # DVR shows 08:52:29 when actual is 08:48:17 -> 4m12s fast
    _, d = store(tmp_path, ("2026-11-26 08:52:29", "2026-11-26 08:48:17"))
    r = convert(d, "2026-11-20 14:00:00", "dvr_to_actual")
    assert r["actual_time"] == "2026-11-20 13:55:48"
    assert r["offset_hms"] == "+00:04:12"
    assert any("Only one measurement" in n for n in r["notes"])
    back = convert(d, r["actual_time"], "actual_to_dvr")
    assert back["dvr_time"] == "2026-11-20 14:00:00"


def test_exact_clock(tmp_path):
    _, d = store(tmp_path, ("2026-11-26 08:48:17", "2026-11-26 08:48:17"))
    r = convert(d, "2026-11-26 08:48:08", "actual_to_dvr")
    assert r["dvr_time"] == "2026-11-26 08:48:08" and r["offset_text"] == "Time is exact"


def test_drift_from_two_measurements(tmp_path):
    # +60 s on Nov 1, +80 s on Nov 11 -> +2 s/day
    _, d = store(tmp_path, ("2026-11-01 12:01:00", "2026-11-01 12:00:00"),
                 ("2026-11-11 12:01:20", "2026-11-11 12:00:00"))
    fit = drift_fit(d["measurements"])
    assert fit["rate_s_per_day"] == pytest.approx(2.0)
    r = convert(d, "2026-11-06 12:00:00", "actual_to_dvr")
    assert r["dvr_time"] == "2026-11-06 12:01:10"
    assert not any("extrapolated" in n for n in r["notes"])
    r2 = convert(d, "2026-10-22 12:00:00", "actual_to_dvr")      # 10 days before -> +40 s
    assert r2["dvr_time"] == "2026-10-22 12:00:40"
    assert any("extrapolated" in n for n in r2["notes"])
    # round trip with drift
    back = convert(d, "2026-10-22 12:00:40", "dvr_to_actual")
    assert back["actual_time"] == "2026-10-22 12:00:00"


def test_dst_warning(tmp_path):
    # measured in November (EST), incident in July (EDT)
    assert dst_warning(dt.datetime(2026, 7, 4, 12), dt.datetime(2026, 11, 26, 8))
    assert not dst_warning(dt.datetime(2026, 11, 20, 12), dt.datetime(2026, 11, 26, 8))
    _, d = store(tmp_path, ("2026-11-26 08:52:29", "2026-11-26 08:48:17"))
    r = convert(d, "2026-07-04 21:00:00", "dvr_to_actual")
    assert any("daylight-saving" in n for n in r["notes"])


def test_store_crud(tmp_path):
    s, d = store(tmp_path, ("2026-11-26 08:52:29", "2026-11-26 08:48:17"))
    m = d["measurements"][0]
    assert m["offset_s"] == 252 and m["reference_source"] == "time.gov" and m["examiner"] == "Det. T"
    s.log_conversion(d["id"], convert(d, "2026-11-20 14:00:00", "dvr_to_actual"), "Suspect enters")
    assert s.get(d["id"])["conversions"][0]["label"] == "Suspect enters"
    assert s.delete_measurement(d["id"], m["id"])
    with pytest.raises(ClockError):
        convert(s.get(d["id"]), "2026-11-20 14:00:00", "dvr_to_actual")
    assert s.delete_dvr(d["id"]) and s.all() == []


def test_dst_setting_applied(tmp_path):
    s = DvrStore(tmp_path)
    for setting, expect in (("Auto DST off", "2026-07-04 22:11:18"), ("Auto DST on", "2026-07-04 21:11:18")):
        d = s.save_dvr({"name": setting, "dst_setting": setting})
        s.add_measurement(d["id"], {"dvr_time": "2026-11-26 08:52:29", "reference_time": "2026-11-26 08:48:17"})
        r = convert(s.get(d["id"]), "2026-07-04 21:15:30", "dvr_to_actual")
        assert r["actual_time"] == expect, (setting, r)
        back = convert(s.get(d["id"]), expect, "actual_to_dvr")
        assert back["dvr_time"] == "2026-07-04 21:15:30"


def test_eastern_rule_matches_2026_dates():
    assert _us_eastern_offset(dt.datetime(2026, 3, 8, 1, 59)) == -5 * 3600
    assert _us_eastern_offset(dt.datetime(2026, 3, 8, 3, 0)) == -4 * 3600
    assert _us_eastern_offset(dt.datetime(2026, 11, 1, 1, 0)) == -4 * 3600
    assert _us_eastern_offset(dt.datetime(2026, 11, 1, 2, 0)) == -5 * 3600


def test_real_local_utc_offset_works_on_this_os():
    # the real (unpatched) function, captured at import: must work on Windows too
    off = _REAL_LOCAL_UTC_OFFSET(dt.datetime(2026, 7, 4, 12))
    assert off % 60 == 0 and abs(off) <= 14 * 3600
