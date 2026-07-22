from __future__ import annotations

import os
import threading
import time
from itertools import count

_counter = count(1)
_lock = threading.Lock()


# Returns True when the VULCAN_TRACE environment variable is set to a truthy value
def _enabled() -> bool:
    value = (os.getenv("VULCAN_TRACE") or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def trace_step(message: str) -> None:
    """
    Print a numbered trace line to stdout when VULCAN_TRACE is enabled.

    Usage:
      - PowerShell: $env:VULCAN_TRACE="1"
      - Bash: export VULCAN_TRACE=1
    """
    if not _enabled():
        return

    with _lock:
        n = next(_counter)

    ts = time.strftime("%H:%M:%S")
    thread_name = threading.current_thread().name
    print(f"[TRACE {n:04d} {ts} {thread_name}] {message}", flush=True)

