"""Stored-XSS probe (Phase 4, V1.2.1) — submits a DiscoveredForm with a
marker payload and checks whether it comes back unescaped, immediately or
on another page. All against httpx.MockTransport.
"""
from urllib.parse import parse_qs

import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig, AuthMode
from app.domain.analysis.dast.crawler import DiscoveredForm
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.verdict import Verdict
from app.domain.analysis.dast.xss_probe import run_stored_xss_probe

TARGET = "https://target.example"


def _session(handler) -> DastSession:
    return DastSession(ActorConfig(auth_mode=AuthMode.NONE), resolve=False, transport=httpx.MockTransport(handler))


def _form(**overrides) -> DiscoveredForm:
    defaults = dict(
        action_url=f"{TARGET}/comments", method="POST", fields=["comment", "csrf_token"],
        source_url=f"{TARGET}/post/1",
    )
    defaults.update(overrides)
    return DiscoveredForm(**defaults)


class TestGating:
    @pytest.mark.asyncio
    async def test_skipped_without_active_mode_by_default(self):
        async with _session(lambda r: httpx.Response(200, text="ok")) as session:
            finding = await run_stored_xss_probe(session, _form(), [])
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION
        assert finding.control_id == "V1.2.1"


def _posted_comment(request: httpx.Request) -> str:
    # Simulates the app decoding the submitted form and storing/echoing the
    # 'comment' field's *value*, not the raw urlencoded request body.
    posted = parse_qs(request.content.decode())
    return posted.get("comment", [""])[0]


class TestReflectedImmediately:
    @pytest.mark.asyncio
    async def test_marker_in_submission_response_fails(self):
        source_html = "<html><body><form method='POST' action='/comments'></form></body></html>"

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, text=source_html)
            return httpx.Response(200, text=f"thanks: {_posted_comment(request)}")

        async with _session(handler) as session:
            finding = await run_stored_xss_probe(session, _form(), [], active_mode=True)
        assert finding.verdict == Verdict.FAIL
        assert "reflected" in finding.note.lower()


class TestStoredReflection:
    @pytest.mark.asyncio
    async def test_marker_found_on_other_page_fails(self):
        source_html = "<html><body><form method='POST' action='/comments'></form></body></html>"
        state = {"last_payload": ""}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                if str(request.url) == f"{TARGET}/wall":
                    return httpx.Response(200, text=f"wall: {state['last_payload']}")
                return httpx.Response(200, text=source_html)
            state["last_payload"] = _posted_comment(request)
            return httpx.Response(200, text="submitted, thanks")

        async with _session(handler) as session:
            finding = await run_stored_xss_probe(
                session, _form(), [f"{TARGET}/wall"], active_mode=True,
            )
        assert finding.verdict == Verdict.FAIL
        assert finding.url == f"{TARGET}/wall"

    @pytest.mark.asyncio
    async def test_marker_escaped_on_other_page_passes(self):
        source_html = "<html><body><form method='POST' action='/comments'></form></body></html>"

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                if str(request.url) == f"{TARGET}/wall":
                    return httpx.Response(200, text="wall: &lt;dastxss&gt; (escaped)")
                return httpx.Response(200, text=source_html)
            return httpx.Response(200, text="submitted, thanks")

        async with _session(handler) as session:
            finding = await run_stored_xss_probe(
                session, _form(), [f"{TARGET}/wall"], active_mode=True,
            )
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_no_reflection_urls_and_no_immediate_reflection_is_inconclusive(self):
        source_html = "<html><body><form method='POST' action='/comments'></form></body></html>"

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, text=source_html)
            return httpx.Response(200, text="submitted, thanks")

        async with _session(handler) as session:
            finding = await run_stored_xss_probe(session, _form(), [], active_mode=True)
        assert finding.verdict == Verdict.INCONCLUSIVE


class TestFieldSubmission:
    @pytest.mark.asyncio
    async def test_csrf_field_value_preserved_other_fields_get_marker(self):
        source_html = (
            "<html><body><form method='POST' action='/comments'>"
            "<input type='hidden' name='csrf_token' value='real-token-123'/>"
            "<input name='comment' value=''/>"
            "</form></body></html>"
        )
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, text=source_html)
            captured["body"] = request.content.decode()
            return httpx.Response(200, text="submitted")

        async with _session(handler) as session:
            await run_stored_xss_probe(session, _form(), [], active_mode=True)

        assert "csrf_token=real-token-123" in captured["body"]
        assert "comment=" in captured["body"]
        assert "dastxss" in captured["body"]

    @pytest.mark.asyncio
    async def test_source_fetch_failure_falls_back_to_crawler_field_names(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                raise httpx.ConnectError("boom")
            captured["body"] = request.content.decode()
            return httpx.Response(200, text="submitted")

        async with _session(handler) as session:
            finding = await run_stored_xss_probe(session, _form(fields=["comment"]), [], active_mode=True)

        assert "comment=" in captured["body"]
        assert finding.verdict == Verdict.INCONCLUSIVE


class TestSubmissionFailure:
    @pytest.mark.asyncio
    async def test_submission_exception_is_not_tested(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, text="<html></html>")
            raise httpx.ConnectError("boom")

        async with _session(handler) as session:
            finding = await run_stored_xss_probe(session, _form(), [], active_mode=True)
        assert finding.verdict == Verdict.NOT_TESTED
