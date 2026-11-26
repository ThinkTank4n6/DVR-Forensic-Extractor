"""File helpers that survive Windows' habit of briefly locking fresh files.

On Windows, os.replace() raises PermissionError (WinError 5, access denied, or
32, sharing violation) while another process holds the destination open for a
moment - Defender, the Search indexer, OneDrive or a backup agent scanning a
file that was just written. Retrying for a few seconds is the standard fix.
"""
from __future__ import annotations

import os
import time

_TRANSIENT_WINERRORS = {5, 32, 33}   # access denied, sharing violation, lock violation


def _transient(exc: OSError) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in _TRANSIENT_WINERRORS


def replace_retry(src, dst, timeout: float = 3.0) -> None:
    """os.replace(src, dst), retried with backoff while the error is transient."""
    delay, waited = 0.01, 0.0
    while True:
        try:
            os.replace(src, dst)
            return
        except OSError as exc:
            if not _transient(exc) or waited >= timeout:
                raise
            time.sleep(delay)
            waited += delay
            delay = min(delay * 2, 0.25)
