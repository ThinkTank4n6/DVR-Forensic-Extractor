"""Version scheme: Year.Month.Release.Build = pre-release, Year.Month.Release = official."""
import re
from pathlib import Path

import dfx

ROOT = Path(__file__).resolve().parent.parent


def _key(v: str):
    return tuple(int(x) for x in v.split("."))


def test_version_file_format_and_package_agree():
    v = (ROOT / "VERSION").read_text().strip()
    assert re.fullmatch(r"\d{4}\.\d{1,2}\.\d+(\.\d+)?", v), v
    assert dfx.__version__ == v
    assert dfx.IS_PRERELEASE == (len(v.split(".")) == 4)


def test_prerelease_builds_sort_before_their_official_release():
    order = ["2026.11.1", "2026.11.1.12", "2026.11.1.13", "2026.11.1.99", "2026.11.2", "2026.12.1", "2026.12.1.1",
             "2026.12.1.2", "2026.12.2", "2027.1.1"]
    assert sorted(order, key=_key) == order


def test_frozen_fallback_matches_version_file():
    src = (ROOT / "dfx" / "__init__.py").read_text()
    assert f'__version__ = "{(ROOT / "VERSION").read_text().strip()}"' in src


def test_release_workflow_decides_kind_from_tag():
    wf = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "prerelease: ${{ steps.kind.outputs.prerelease }}" in wf
    assert "does not match VERSION" in wf
    assert "must be higher than the highest existing tag" in wf and "fetch-depth: 0" in wf
