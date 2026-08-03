from collections import deque
from time import monotonic

from fastapi import HTTPException, Request, status

from app.core.config import settings

# In-memory, per-process sliding-window rate limiter. Two known limitations
# that a distributed limiter (e.g. Redis-backed) would remove, not addressed
# here since they're an infrastructure decision rather than a code-level bug:
#   - Per-process only: each worker/instance has its own independent buckets,
#     so the effective limit under N processes is roughly limit * N.
#   - No cross-instance persistence: a restart clears all counters.
_buckets: dict[str, deque[float]] = {}

_calls_since_sweep = 0
_SWEEP_INTERVAL = 1000
# Generous fixed staleness threshold for the periodic sweep, independent of
# any single caller's window_seconds — every current call site uses a window
# of 900-3600s, so anything untouched for an hour is stale for all of them.
_SWEEP_STALE_AFTER_SECONDS = 3600


def _resolve_client_ip(request: Request) -> str:
    hop_count = settings.TRUSTED_PROXY_HOP_COUNT
    if hop_count > 0:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            chain = [part.strip() for part in forwarded_for.split(",") if part.strip()]
            # The rightmost `hop_count` entries were appended by proxies we
            # trust; the one just past them is the real client. Anything to
            # its left is client-supplied and not trustworthy.
            index = len(chain) - 1 - hop_count
            if 0 <= index < len(chain):
                return chain[index]
    return request.client.host if request.client else "unknown"


def _sweep_expired_buckets(now: float) -> None:
    # Bounds _buckets' size against one-time visitors: a key whose deque
    # trims to empty on its own next access gets cleaned up inline in
    # check_rate_limit, but a key that's never accessed again after its
    # window expires would otherwise sit there forever. Runs every
    # _SWEEP_INTERVAL calls rather than on every call, since it's O(buckets).
    stale_keys = [
        key for key, entries in _buckets.items()
        if not entries or now - entries[-1] > _SWEEP_STALE_AFTER_SECONDS
    ]
    for key in stale_keys:
        del _buckets[key]


def check_rate_limit(request: Request, bucket: str, limit: int, window_seconds: int) -> None:
    global _calls_since_sweep

    host = _resolve_client_ip(request)
    key = f"{bucket}:{host}"
    now = monotonic()

    _calls_since_sweep += 1
    if _calls_since_sweep >= _SWEEP_INTERVAL:
        _calls_since_sweep = 0
        _sweep_expired_buckets(now)

    entries = _buckets.get(key)
    if entries:
        while entries and now - entries[0] > window_seconds:
            entries.popleft()
        if not entries:
            del _buckets[key]
            entries = None

    if entries and len(entries) >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Try again later.",
        )

    _buckets.setdefault(key, deque()).append(now)
