"""
Rate limiter tests.

Covers the sliding-window mechanics themselves, plus three gaps fixed after
initial review: (1) it used to key on request.client.host unconditionally,
which is the reverse-proxy IP rather than the real client behind any
deployment with a proxy in front — now opt-in via TRUSTED_PROXY_HOP_COUNT,
defaulting to the old (safe) direct-peer behavior; (2) _buckets grew one
entry per unique (bucket, host) ever seen and never shrank, a slow memory
leak over a long-running process — now cleaned up both inline (per-key, once
its own deque empties) and via a periodic full sweep (for one-time visitors
whose key is never touched again).
"""
import pytest

from app.core import rate_limit as rl
from app.core.config import settings


class _FakeClient:
    def __init__(self, host: str):
        self.host = host


class _FakeRequest:
    def __init__(self, host: str = "1.2.3.4", headers: dict | None = None):
        self.client = _FakeClient(host)
        self.headers = headers or {}


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    rl._buckets.clear()
    rl._calls_since_sweep = 0
    yield
    rl._buckets.clear()
    rl._calls_since_sweep = 0


class TestSlidingWindow:
    def test_allows_requests_under_the_limit(self):
        req = _FakeRequest()
        for _ in range(3):
            rl.check_rate_limit(req, "test-bucket", limit=3, window_seconds=60)

    def test_blocks_once_limit_is_reached(self):
        req = _FakeRequest()
        for _ in range(3):
            rl.check_rate_limit(req, "test-bucket", limit=3, window_seconds=60)
        with pytest.raises(Exception) as exc_info:
            rl.check_rate_limit(req, "test-bucket", limit=3, window_seconds=60)
        assert exc_info.value.status_code == 429

    def test_expired_entries_free_up_the_window(self, monkeypatch):
        fake_now = [1000.0]
        monkeypatch.setattr(rl, "monotonic", lambda: fake_now[0])

        req = _FakeRequest()
        for _ in range(3):
            rl.check_rate_limit(req, "test-bucket", limit=3, window_seconds=10)
        with pytest.raises(Exception):
            rl.check_rate_limit(req, "test-bucket", limit=3, window_seconds=10)

        fake_now[0] += 11  # past the 10s window
        rl.check_rate_limit(req, "test-bucket", limit=3, window_seconds=10)  # no raise

    def test_different_hosts_have_independent_buckets(self):
        req_a = _FakeRequest(host="1.1.1.1")
        req_b = _FakeRequest(host="2.2.2.2")
        for _ in range(3):
            rl.check_rate_limit(req_a, "test-bucket", limit=3, window_seconds=60)
        # req_b's own bucket is untouched, even though the same "test-bucket"
        # name is used.
        rl.check_rate_limit(req_b, "test-bucket", limit=3, window_seconds=60)

    def test_different_buckets_for_the_same_host_are_independent(self):
        req = _FakeRequest()
        for _ in range(3):
            rl.check_rate_limit(req, "login", limit=3, window_seconds=60)
        rl.check_rate_limit(req, "register", limit=3, window_seconds=60)


class TestTrustedProxyResolution:
    def test_default_hop_count_zero_ignores_xff_header(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOP_COUNT", 0)
        req = _FakeRequest(host="1.2.3.4", headers={"x-forwarded-for": "9.9.9.9"})
        assert rl._resolve_client_ip(req) == "1.2.3.4"

    def test_hop_count_one_extracts_the_correct_xff_entry(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOP_COUNT", 1)
        # chain: real_client, trusted_proxy — with one trusted hop, the real
        # client is one position in from the right.
        req = _FakeRequest(headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1"})
        assert rl._resolve_client_ip(req) == "203.0.113.7"

    def test_hop_count_beyond_chain_length_falls_back_to_direct_peer(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOP_COUNT", 5)
        req = _FakeRequest(host="1.2.3.4", headers={"x-forwarded-for": "9.9.9.9"})
        assert rl._resolve_client_ip(req) == "1.2.3.4"

    def test_missing_xff_header_falls_back_to_direct_peer(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOP_COUNT", 1)
        req = _FakeRequest(host="1.2.3.4")
        assert rl._resolve_client_ip(req) == "1.2.3.4"


class TestBucketCleanup:
    def test_bucket_entry_removed_once_its_window_fully_expires(self, monkeypatch):
        fake_now = [1000.0]
        monkeypatch.setattr(rl, "monotonic", lambda: fake_now[0])

        req = _FakeRequest()
        rl.check_rate_limit(req, "test-bucket", limit=5, window_seconds=10)
        key = "test-bucket:1.2.3.4"
        assert key in rl._buckets

        fake_now[0] += 11
        # Next call for the same key trims its own now-expired entry and,
        # since that empties the deque, removes the dict entry entirely
        # before re-adding the new one — so the dict never accumulates a
        # dangling empty deque.
        rl.check_rate_limit(req, "test-bucket", limit=5, window_seconds=10)
        assert len(rl._buckets[key]) == 1

    def test_periodic_sweep_removes_untouched_stale_keys(self, monkeypatch):
        fake_now = [1000.0]
        monkeypatch.setattr(rl, "monotonic", lambda: fake_now[0])
        monkeypatch.setattr(rl, "_SWEEP_STALE_AFTER_SECONDS", 10)

        one_time_visitor = _FakeRequest(host="9.9.9.9")
        rl.check_rate_limit(one_time_visitor, "test-bucket", limit=5, window_seconds=3600)
        assert "test-bucket:9.9.9.9" in rl._buckets

        fake_now[0] += 11  # past _SWEEP_STALE_AFTER_SECONDS, never revisited
        rl._sweep_expired_buckets(fake_now[0])
        assert "test-bucket:9.9.9.9" not in rl._buckets

    def test_sweep_runs_automatically_every_sweep_interval(self, monkeypatch):
        fake_now = [1000.0]
        monkeypatch.setattr(rl, "monotonic", lambda: fake_now[0])
        monkeypatch.setattr(rl, "_SWEEP_STALE_AFTER_SECONDS", 10)
        monkeypatch.setattr(rl, "_SWEEP_INTERVAL", 2)

        stale_visitor = _FakeRequest(host="8.8.8.8")
        rl.check_rate_limit(stale_visitor, "b", limit=5, window_seconds=3600)
        assert "b:8.8.8.8" in rl._buckets

        fake_now[0] += 11
        other = _FakeRequest(host="1.1.1.1")
        rl.check_rate_limit(other, "b", limit=5, window_seconds=3600)  # call 2 -> triggers sweep
        assert "b:8.8.8.8" not in rl._buckets
