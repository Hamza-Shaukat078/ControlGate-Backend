"""
ASVS compliance service — merges evidence from all four detection modules
(taint engine + rule catalog, config inspector, dependency scanner, dynamic
probe) plus manual attestations into one ASVSControlResult per control, and
aggregates those into the compliance summary the frontend consumes.

Verdict policy per detection_strategy:
  static_code         — a rule for this control fired: "vulnerable"-polarity
                        finding -> fail; "compliant"-polarity marker finding
                        -> pass. No finding at all: pass if every rule tagged
                        for this control is vulnerable-polarity (ran across
                        the whole repo, found nothing); not_tested if the
                        control is only covered by a weak presence marker
                        that didn't fire (regex absence isn't proof of
                        absence for those).
  config_inspection   — any "fail" finding for the control wins; else "pass"
                        if any finding at all; else not_tested (no config
                        file of the relevant type was found in the repo).
  dependency_scan     — V15.2.1 only; taken directly from the dependency
                        scanner's own SLA evaluation.
  dynamic_probe       — taken directly from the live-probe finding; not_tested
                        if no target_url was supplied for the scan.
  manual_attestation  — the human-submitted answer if one exists, else
                        not_tested.

A "fail" from any source always wins when a control has evidence from more
than one source (e.g. V3.4.1 gets both a static nginx reading and a live
HTTP header check) — conservative-by-default, consistent with how the rest
of this scanner treats overlapping evidence.
"""
import asyncio
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Optional
from xml.sax.saxutils import escape as _xml_escape

from motor.motor_asyncio import AsyncIOMotorDatabase

from semantic_engine.query_store.loader import get_query_store
from app.db.mongo import to_object_id
from app.enums.role import UserRole

logger = logging.getLogger(__name__)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, Preformatted, Flowable, Image,
    )
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab not installed. ASVS PDF export will not be available.")


def _pdf_text(text: Optional[str]) -> str:
    """Escapes '&', '<', '>' before handing text to reportlab's Paragraph —
    Paragraph runs its content through a mini XML/markup parser (that's how
    the `<b>`/`<br/>`/`<font>` tags we write ourselves get rendered), so any
    *untrusted or just plain unescaped* text containing a literal '<' fails
    the whole PDF export with a "parse ended with N unclosed tags" error.
    Real trigger: an ASVS control description that literally reads
    "...remove scripting elements (such as <script> and <foreignObject>)...".
    Every piece of dynamic text (control descriptions, LLM-written summary/
    explanation text, finding evidence notes, repo/branch names) must go
    through this before being embedded in an f-string alongside our own
    literal markup tags — escape only the dynamic piece, never the
    already-assembled string, or our own tags get escaped too."""
    return _xml_escape(text or "")

from semantic_engine.classifier.llm_pool import RoleAwareLLMPool

ASVS_LEVELS = ["L1", "L2", "L3"]
_LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3}
_VERDICT_KEYS = ["pass", "fail", "n_a", "manual_review", "not_tested"]

_ATTESTATION_PROCESS = [
    "Review the exact scan scope: scan id, repo/branch or dynamic target, and this control text.",
    "Check scanner evidence and confirm whether automated results leave this control requiring human judgment.",
    "Verify the implementation or operational process for this scan scope only.",
    "Attach proof or write evidence notes that explain what was reviewed and why the verdict is valid.",
    "Submit pass, fail, manual_review, or n_a. The record is saved against this scan id and control id.",
]

_ATTESTATION_REQUIRED_PROOF = [
    "Evidence must name the reviewed system, repository/branch/target, or operational process.",
    "Acceptable proof: uploaded document, screenshot, test output, ticket, code review, policy excerpt, or detailed reviewer notes.",
    "A pass/n_a/fail/manual_review answer without proof is rejected.",
]

# Set on a finding's llm_classification.explanation when the classifier could not
# actually get an LLM opinion (rate-limited / quota-exhausted / disabled) and fell
# back to the bare static/taint match with no semantic confirmation. A "fail" built
# entirely out of these is a guess, not a verified result — see _merge_static.
_UNCONFIRMED_LLM_MARKERS = {
    "LLM unavailable — pattern-based detection only",
    "LLM cap reached — static analysis only",
}

# Controls whose catalog detection_strategy is "config_inspection" but which
# _compute_result also accepts a second, independent source of evidence for:
# V3.5.8 accepts a static rule-catalog match (a compliant-polarity finding
# tagged with this control_id in a rule's asvs_controls); V3.4.1/V13.4.6
# accept a live dynamic_probe result (DynamicProbe._check_hsts_header /
# _check_version_disclosure exist specifically to cross-check these two —
# see their docstrings). A rule/probe mapped to one of these is NOT an inert
# mapping — see _merge_config_or_compliant_static / _merge_config_or_dynamic
# below.
HYBRID_STATIC_ELIGIBLE_CONTROLS = {"V3.5.8", "V3.4.1", "V13.4.6"}

# Controls whose catalog detection_strategy is "manual_attestation" but which
# _compute_result also accepts a confirmed vulnerable-polarity static finding
# for: V1.1.1 ("decode/canonicalize untrusted input exactly once, before
# validation") accepts DOUBLE_DECODE_CANONICALIZATION (queries.json) — a
# narrow, high-confidence slice of the control (decode wrapping decode in the
# same expression). V1.5.3 ("different parsers for the same data type behave
# consistently") accepts MANUAL_URL_HOST_PARSING — a hand-rolled URL host
# extraction is itself the "different, less careful implementation" the
# control warns about, readable from one file. V2.3.3 ("a business
# transaction and its writes are atomic") accepts
# MULTI_TABLE_WRITE_WITHOUT_TRANSACTION — clustered DB writes with no visible
# transaction boundary anywhere in the file is always at least a
# partial-failure risk, independent of whether this particular business
# transaction needed atomicity. This is NOT symmetric with
# HYBRID_STATIC_ELIGIBLE_CONTROLS above: those controls accept a second source
# for BOTH pass and fail. Here, a confirmed static hit can fail the control
# outright (real, independent evidence of the violation), but its absence can
# never pass it — proving the full property holds everywhere requires
# whole-pipeline/cross-service visibility (framework-level implicit decoding,
# a second parser in a service this scanner never sees, whether these writes
# were even meant to be one business transaction) it doesn't have, so pass
# still requires a human. See _merge_attestation_or_vulnerable_static below —
# the same method handles every control in this set; nothing here is
# V1.1.1-specific.
#
# V6.3.4 ("no undocumented or backdoor authentication pathways") accepts
# AUTH_BACKDOOR_BYPASS (queries.json) — a hardcoded admin/master credential
# check, a DEBUG/env-var auth-skip flag, or a magic bypass header/token found
# near authentication code is real, independent evidence of exactly the kind
# of pathway the control prohibits. Same non-symmetric reasoning as every
# other member of this set: a confirmed hit fails the control outright, but
# the pattern firing zero times never proves the property — the control's own
# description says as much ("absence can't be proven via static pattern
# matching"), so a clean scan still falls through to attestation (the full
# authentication-flow audit V6.1.3/V6.3.4's own verification steps call for).
#
# V10.3.2 ("authorization decisions use validated token claims, not merely a
# token's presence") reuses two EXISTING rules rather than a new one:
# JWT_EXP_NBF_NOT_VERIFIED and JWT_MISSING_AUDIENCE_CHECK (both already
# static_code evidence for V9.2.1/V9.2.3/V10.3.1) now also carry
# "V10.3.2" in their asvs_controls. A JWT decode call that's confirmed to
# skip expiry/not-before or audience verification is real, independent
# evidence the resource server can't be checking validated claims — it's
# trusting whatever the token itself claims, unverified. Same non-symmetric
# policy: a confirmed hit fails V10.3.2 outright, but clean JWT-handling
# code doesn't prove every authorization decision in the app validates
# every relevant claim (opaque/introspected tokens, claims JWT_MISSING_
# AUDIENCE_CHECK doesn't look at) — that still needs a human reading each
# call site, per the control's own verification steps.
HYBRID_ATTESTATION_ELIGIBLE_CONTROLS = {"V1.1.1", "V1.5.3", "V2.3.3", "V6.3.4", "V10.3.2"}

# Same idea as HYBRID_ATTESTATION_ELIGIBLE_CONTROLS above, but the second
# evidence source is a live DAST finding (summary["dynamic_findings"]) rather
# than a static one (summary["vulnerabilities"]) — kept as its own set/method
# rather than folded into the static one because the two read different
# fields with different shapes, same reason _merge_config_or_compliant_static
# and _merge_config_or_dynamic are separate functions rather than one that
# branches on evidence type. V3.7.3 ("outbound redirects show a cancelable
# warning") accepts REDIRECT_WARNING_LIVE (redirect_warning_probe.py) — a
# live headless-browser click that lands on the external host immediately,
# with no interstitial observed, is direct behavioral evidence no static
# read of the page's markup could produce (a modal element existing in the
# DOM proves nothing about whether it actually intercepts navigation). See
# _merge_attestation_or_dynamic_finding below. Same non-symmetric shape as
# the static set: a confirmed live failure fails the control outright, but a
# clean probe result never passes it on its own — the probe's own PASS
# verdict is deliberately issued at lower confidence than its FAIL (see that
# module's docstring) precisely because "the page didn't navigate away" is
# far weaker evidence than "the page did."
#
# V4.2.2 accepts REQUEST_SMUGGLING (checks.py) — an ambiguous Content-Length/
# Transfer-Encoding request that leaks a marker into the response is direct
# evidence the framing property this control requires doesn't hold. V4.2.4
# accepts CRLF_HEADER_REFLECTION (checks.py) — a reflection-based
# approximation of the same header-injection property (see that rule's own
# description in dynamic_queries.json for what it doesn't prove). Both rules
# were already tagged with these control_ids in dynamic_queries.json and
# already landing in summary["dynamic_findings"] — they just had no merge
# path reading them before this, so every live hit was silently dropped and
# the control stayed manual_attestation-only regardless of what the DAST
# engine actually found (same class of gap the module docstring above
# documents two prior fixes for).
#
# V4.4.3/V4.4.4 accept WEBSOCKET_TOKEN_DERIVED_FROM_SESSION /
# WEBSOCKET_TOKEN_UNAUTH_ISSUANCE (checks.py) — both path-shape-gated live
# checks against a discovered WebSocket/realtime token-issuance endpoint;
# see their own docstrings for exactly what a clean PASS does and doesn't
# prove.
#
# V6.4.3 (password reset can't bypass MFA), V6.6.2 (OOB code bound to its
# originating request), and V6.8.3 (SAML assertions can't be replayed) are
# this set's first members with no *built-in* probe behind them — none of
# these flows (a real reset-token from an inbox, a live OTP transaction, a
# captured SAML assertion) can be generically discovered the way a logout
# link or a WebSocket token endpoint can. What already exists is
# DynamicScenarioRequest (app/schemas/scan.py's dynamic_scenarios) — the
# same app-specific-steps mechanism V2.3.1/V7.4.3/V8.3.2/V8.3.3 all rely on
# too (V2.3.4 below rides DynamicRaceProbeRequest instead, its own
# concurrent-request shape). A tester scripts the concrete steps (submit a
# real reset token, replay a captured OTP against an unrelated transaction
# id, replay a captured SAML assertion) with
# asvs_controls=["V6.4.3"|"V6.6.2"|"V6.8.3"], and scenario_runner.py's
# run_scenario already produces a DynamicFinding tagged with that
# control_id. Before this, that finding landed in
# summary["dynamic_findings"] and was silently dropped — these controls
# weren't in this set, so _merge_attestation (no dynamic_findings read at
# all) is what actually ran. This only wires the read path; it doesn't
# change what still requires a human to author the scenario steps.
#
# V7.4.3 (credential change terminates other sessions) is the flagship
# example DynamicScenarioRequest's own docstring names for this same
# app-specific-steps mechanism (config.py's second_actor, api_scenario.py,
# and test_dast_api_scenario.py all already reference a
# CRED_CHANGE_KILLS_SESSIONS scenario_id for it) — yet it was never added
# to this set, so exactly the same silently-dropped-finding gap V4.2.2/
# V4.2.4 document above applied to the one control this whole mechanism
# was built to demonstrate. Same fix, same non-symmetric policy: a
# tester-scripted fail/confirmed result now fails the control; a human
# still has to author the two-actor steps and still has to attest pass.
#
# V7.4.4 (logout control visible on every authenticated page) DOES get a
# built-in probe: check_logout_visible_on_every_page (logout_discovery.py)
# sweeps every URL this scan already crawled through the authenticated
# session, looking for a logout-shaped link/button in the markup. A page
# with none is real, specific evidence — but per that function's own
# docstring, a hit everywhere only proves markup presence, never actual
# visibility (scrolling, a collapsed mobile menu, an error state), which is
# what this control actually asks about — so PASS still isn't decisive here
# either, same as every other member of this set.
#
# V8.3.2 (authorization changes take effect immediately, or a mitigating
# control exists) is the SECOND flagship dynamic_scenarios example named
# right next to V7.4.3 in scan.py/api_scenario.py's docstrings — same
# silently-dropped-finding bug, same fix. One real caveat, unlike V7.4.3:
# this control's own wording has an escape hatch ("...OR, where this is
# not possible, that mitigating controls exist such as alerting on
# privilege changes or the ability to revert them") that a scripted
# revoke-then-recheck scenario cannot see either way — a FAIL only proves
# "not immediate," never "and no mitigating control exists anywhere in this
# org's process." Wired anyway, same conservative-by-default posture this
# module's own docstring states for every other source of evidence
# (REDIRECT_WARNING_LIVE, the boolean-blind SQLi FAIL, ... — "single test
# run, not a confirmed exploit chain" is already how plenty of this
# engine's FAILs read); a false fail here is correctable by an attestation
# that documents the mitigating control, same as any other finding a human
# reviews before treating a scan result as final.
#
# V8.3.3 (access decisions use the ORIGINATING subject's permissions, not
# an intermediary's — confused-deputy prevention) is new scope, not a
# pre-existing bug: unlike the controls above, nothing in this codebase
# already names or scripts it. It's included because the test it asks for
# reduces to something dynamic_scenarios already expresses trivially — a
# low-privileged actor's session requesting the sensitive action through
# the intermediary, asserting it's still denied — and adding a
# control_id to this set is zero-cost until someone actually scripts it
# (no scenario tagged V8.3.3 → this set never sees a matching finding, same
# as any other member with no dynamic_scenarios supplied this scan).
#
# V2.3.1 (step-skipping in a multi-step business process) is the other
# control DynamicScenarioRequest's own docstring names as an example
# ("V2.3.1 (step-skipping)") without ever being added to this set — same
# silently-dropped-finding gap as V7.4.3/V8.3.2, just for the generic
# scenario mechanism's original flagship use case instead of a
# session/authz-specific one.
#
# V2.3.4 (race-condition/double-submit) is the one member of this
# extension with an actual dedicated request shape — DynamicRaceProbeRequest
# (concurrent, not sequential; see race_probe.py) — rather than riding
# generic dynamic_scenarios. Same gap regardless: race_probe.py's
# run_race_probe has produced a DynamicFinding(control_id="V2.3.4") since
# it was built, and nothing in this module ever read it until now.
#
# V10.4.x/V10.7.1 (OAuth/OIDC authorization-server live-protocol checks) are
# new scope, same reasoning as V8.3.3: nothing pre-existing names them, but
# each one reduces to a small number of scripted requests dynamic_scenarios
# already expresses — a tester who knows the app's OAuth endpoints supplies
# the real client/code/token values (this scanner has no way to discover a
# target's OAuth client registry or obtain valid grants on its own):
#   V10.4.1  redirect_uri tamper (trailing slash/subdomain/traversal) -> reject
#   V10.4.2  replay a used authorization code -> reject; reuse the token it
#            issued -> also reject (revoked)
#   V10.4.3  wait past the code's max lifetime, then exchange -> reject
#            (needs Step.delay_seconds — see its own docstring)
#   V10.4.4  token/password grant against any client -> reject outright
#   V10.4.5  reuse an already-rotated refresh token -> reject, AND every
#            token issued under that authorization -> also reject
#   V10.4.7  malformed dynamic-client-registration metadata -> reject
#   V10.4.11 request over-broad scope -> granted scope body must NOT
#            contain the disallowed one (needs the body_not_contains
#            assertion type — see scenario_runner.py)
#   V10.4.12 disallowed response_mode outside a validated PAR/JAR request
#            -> reject
#   V10.4.13 authorization-code grant without a prior PAR push -> reject
#   V10.4.14 a sender-constrained token used without its proof (no DPoP
#            header / wrong client cert) -> reject
#   V10.4.15 tampered authorization_details submitted outside the
#            backend-originated PAR/JAR path -> reject
#   V10.4.16 confidential-client auth via a bare client_secret where mTLS/
#            private_key_jwt is required -> reject; replay a captured
#            client-authentication assertion -> also reject
#   V10.7.1  a second, scope-expanded authorization request re-shows a
#            consent redirect rather than silently reusing the prior grant
#            (needs a redirect_location_contains/body_contains assertion,
#            not just a status code — both outcomes are a 302)
# All exist purely to be scripted against; a scan with no dynamic_scenarios
# tagged with one of these control_ids never produces a matching finding,
# same zero-cost-until-used reasoning as V8.3.3.
#
# V11.2.5 ("cryptographic modules fail securely, no padding-oracle/timing
# side channel") gets a real built-in probe, not just a dynamic_scenarios
# tag: padding_oracle_probe.py's TimingComparisonProbeConfig/
# run_timing_comparison_probe, fed by a DEDICATED request shape
# (dynamic_timing_probes/DynamicTimingComparisonProbeRequest — status/body
# assertions can't express "compare wall-clock timing of two fixed
# payloads", so this doesn't fit the generic Step/Assertion vocabulary the
# other members of this set ride). This scanner still can't generate valid
# ciphertext for a target's own encryption scheme, so the tester supplies
# both payload variants (e.g. valid-padding-wrong-content vs.
# invalid-padding); the probe only reports whether they're timing-
# distinguishable. A confirmed timing distinction is real, specific
# evidence and fails the control — but per padding_oracle_probe.py's own
# docstring, it's a heuristic indicator (best-effort, samples-based), never
# a proven plaintext-recovery exploit, so it's FAIL, never CONFIRMED; a
# clean comparison only proves those two specific payloads aren't
# distinguishable, so PASS still isn't decisive here either.
#
# V17.3.2 ("signaling server resilient to malformed messages") also gets a
# real built-in probe: websocket_fuzz_probe.py's WebSocketFuzzProbeConfig/
# run_websocket_fuzz_probe, fed by dynamic_signaling_fuzz_probes/
# DynamicSignalingFuzzProbeRequest — a dedicated request shape again,
# because this is the one probe in the whole engine that isn't
# HTTP-request/response-shaped at all (it drives the `websockets` library
# directly). Ships with a built-in default payload corpus (truncated JSON,
# type confusion, an oversized field, ...) so a tester doesn't have to
# invent one from scratch. A FAIL here means a fresh handshake stopped
# succeeding immediately after a specific payload — real, specific evidence
# the listener crashed or hung — never CONFIRMED (the probe proves the
# listener stopped responding, not which internal fault caused it). A clean
# run only proves the built-in/supplied corpus didn't crash it, not
# immunity to the much larger space a real fuzzing campaign would cover, so
# PASS still isn't decisive here either.
#
# V17.2.4/V17.2.5/V17.2.7/V17.2.3 (webrtc_probe.py, aiortc-dependent — see
# its own module docstring) round out the WebRTC tier:
#   V17.2.4  malformed raw datagrams at the media transport -> the
#            connection-liveness oracle, same shape as V17.3.2 one layer
#            down (RunMalformedPacketProbe)
#   V17.2.5/V17.2.7  N other real legitimate sessions held open
#            concurrently, control session's own media must keep flowing
#            (run_media_flood_probe) — same test either way, V17.2.7 is
#            just the recording-session-specific tag
#   V17.2.3  the one member of this whole set needing TWO connections: a
#            forged, auth-corrupted SRTP packet must not get relayed to a
#            second "observer" connection (run_srtp_auth_enforcement_probe)
#            — gated on a baseline check (does an otherwise-identical
#            VALID forged packet get relayed at all) so a clean result
#            against a non-relaying target degrades to NOT_TESTED instead
#            of a meaningless false PASS; see its own docstring
# All fail-only like every other probe-backed member here: real,
# reproduced evidence of degradation/leakage fails the control outright,
# but a clean run only covers the specific corpus/duration/connection
# count actually exercised, never CONFIRMED, never decisive as a PASS.
HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS = {
    "V2.3.1", "V2.3.4", "V3.7.3", "V4.2.2", "V4.2.4", "V4.4.3", "V4.4.4",
    "V6.4.3", "V6.6.2", "V6.8.3", "V7.4.3", "V7.4.4", "V8.3.2", "V8.3.3",
    "V10.4.1", "V10.4.2", "V10.4.3", "V10.4.4", "V10.4.5", "V10.4.7",
    "V10.4.11", "V10.4.12", "V10.4.13", "V10.4.14", "V10.4.15", "V10.4.16",
    "V10.7.1", "V11.2.5", "V17.2.3", "V17.2.4", "V17.2.5", "V17.2.7", "V17.3.2",
}

# Same idea again, but the second evidence source is CapabilityChecker's
# LLM-judged side-channel (summary["capability_findings"]) rather than a
# taint-engine rule or a DAST finding — kept separate for the same reason
# the static/dynamic sets above are separate (different field, different
# shape, see _merge_attestation_or_capability_finding). V6.6.1 ("SMS/
# telephony OTP only used with a validated phone number, plus a genuine
# alternate method") and V6.8.1 ("accounts from different IdPs linked only
# with proof of ownership, never by email-string match alone") are both
# real code-implementation questions CapabilityChecker is already built to
# answer (unlike V6.1.2/V6.1.3, which ask what application DOCUMENTATION
# says rather than what the code does — no keyword/LLM check here can
# stand in for reading that doc, so those two stay plain manual_attestation
# with no hybrid path). CapabilityChecker never returns "fail" for a
# capability it found no trace of at all (see its own
# implemented=False -> None handling) — a fail here only ever means the
# LLM found the relevant code (an SMS-OTP send call, an IdP account-link
# call) and judged it incorrect, which is exactly the same
# confirmed-and-specific bar the static/dynamic sets require. A "pass"
# verdict is never decisive on its own — same asymmetric policy as
# everywhere else in this module.
#
# V7.6.2 ("session creation requires explicit user consent, particularly
# for federated/SSO logins") joins for the same reason: whether a real
# consent step exists is a UX/flow question on its face, but "does the SSO
# callback route go straight from the IdP redirect to session issuance, or
# through a distinct consent-confirmation step first" is a code-shape
# question CapabilityChecker can answer the same way it answers V6.6.1/
# V6.8.1 — a silent auto-login is a specific, findable absence in the
# callback handler, not a matter of taste. Whether the consent SCREEN ITSELF
# is clear/prominent (the perceptual half of "explicit") still isn't
# something code inspection can judge, so a "pass" still isn't decisive.
#
# V10.7.2 ("the consent screen clearly and accurately shows what access is
# being granted") is the same split as V7.6.2: whether the copy actually
# reads clearly is a human wording judgment, but "does the consent screen
# render the ACTUAL requested scopes dynamically, or a hardcoded generic
# string regardless of what's being requested" is a findable code-shape
# question — a template that never references the scope/permission list at
# all can't possibly be accurate, no matter how well-written its static
# text is.
#
# V11.2.2 ("crypto agility — algorithms/key sizes can be swapped without
# major architectural rework") joins the same way: whether a swap is
# actually easy is an effort ESTIMATE only a human can make, but "does the
# code route algorithm/key-size choices through one centralized, config-
# driven abstraction, or hardcode them at each call site" is a findable
# code-shape question — hardcoded algorithm names scattered across many
# call sites is itself real evidence a swap wouldn't be a config change.
#
# V15.4.4 ("resource allocation policies prevent thread starvation under
# load") joins for the narrowest reason yet: the control's own text says
# starvation-under-load needs load testing, not code inspection — but
# whether a thread/worker/process pool is created with an EXPLICIT size
# bound vs. left unbounded is a plain code-shape fact. An unbounded pool
# is real evidence of the starvation risk this control warns about; a
# bounded one is necessary but not sufficient (fair scheduling, actual
# behavior under a mixed fast/slow load still need a human), so PASS
# still isn't decisive here either.
HYBRID_ATTESTATION_CAPABILITY_ELIGIBLE_CONTROLS = {
    "V6.6.1", "V6.8.1", "V7.6.2", "V10.7.2", "V11.2.2", "V15.4.4",
}

# Fourth and last evidence source: summary["dependency_findings"] — the SAME
# generic per-dependency OSV.dev results _merge_dependency already reads for
# V15.2.1's evidence list, not a new scan or a new query. V17.2.6 ("DTLS
# ClientHello race condition, via either a known-vulnerable-version check or
# an active race-condition test") explicitly names the version-check as the
# easier, always-available half of itself — and this scanner already fetches
# every dependency's known-vulnerability record from OSV for V15.2.1, so
# reusing it here costs nothing new. A confirmed match (an OSV/CVE record
# whose text names both a DTLS/ClientHello handshake context AND a race
# condition) is real, specific evidence of exactly the CVE class this
# control asks about, and fails it outright. No match is NOT proof the
# active half of the control (a live race-condition test against the
# running server) would also pass — the control's own wording keeps that as
# a fallback exactly because a clean dependency scan only rules out
# *already-published* vulnerabilities, so PASS still isn't decisive here.
HYBRID_ATTESTATION_DEPENDENCY_ELIGIBLE_CONTROLS = {"V17.2.6"}

_VERDICT_HEX = {
    "pass": "#16a34a",
    "fail": "#dc2626",
    "n_a": "#64748b",
    "manual_review": "#2563eb",
    "not_tested": "#94a3b8",
}


_LOGO_ICON_PATH = Path(__file__).resolve().parent.parent / "assets" / "logo-icon.png"

if REPORTLAB_AVAILABLE:
    def _control_gate_logo(size: float = 76) -> Flowable:
        """The official ControlGate mark (app/assets/logo-icon.png — a square
        crop of frontend/public/logo.png's icon glyph, transparent background)
        for the PDF cover page. A plain reportlab Image, not a hand-drawn
        vector shape — the mark itself is the source of truth now, not a
        redrawn approximation of it."""
        img = Image(str(_LOGO_ICON_PATH), width=size, height=size)
        img.hAlign = "CENTER"
        return img

_report_pool: Optional["RoleAwareLLMPool"] = None


def _get_report_pool() -> "RoleAwareLLMPool":
    """Lazy singleton — GPT-4o (via the GitHub Models free tier) writes the report's
    executive summary, with automatic fallback to other models if it's unavailable."""
    global _report_pool
    if _report_pool is None:
        _report_pool = RoleAwareLLMPool(
            role="report",
            timeout=30,
            system_prompt=(
                "You are a senior application security consultant writing the executive "
                "summary of an OWASP ASVS 5.0.0 compliance report for a client. "
                "Write 2-4 concise, professional paragraphs of plain prose — no headings, "
                "no bullet points, no markdown formatting. Summarize the overall compliance "
                "posture, call out the most significant risk areas, and give a general sense "
                "of remediation priority. Base every claim strictly on the data supplied in "
                "the user message — never invent findings, control IDs, file names, or "
                "numbers that are not present in that data."
            ),
            min_interval_ms=250,
        )
    return _report_pool


def _level_includes(control_level: str, target_level: str) -> bool:
    return _LEVEL_ORDER.get(control_level, 99) <= _LEVEL_ORDER.get(target_level, 0)


def _not_tested(control_id: str, scan_id: Optional[str], reason: Optional[str] = None) -> dict:
    return {
        "control_id": control_id, "scan_id": scan_id, "verdict": "not_tested",
        "confidence": None, "evidence": [], "llm_explanation": None,
        "reviewed_by": None, "reviewed_at": None, "reason": reason,
        "pass_basis": None, "fail_basis": None,
    }


def _evidence_from_vuln(v: dict, dynamic_by_static_id: Optional[dict] = None) -> dict:
    """Evidence item for a static-code (taint-engine/rule-catalog) finding —
    includes the actual code snippet, not just file:line, so a control's
    pass/fail can be verified by reading the code that produced it instead of
    just trusting the verdict.

    dynamic_by_static_id (bridge_static_finding_id -> DynamicFinding dict,
    built once per control from summary["dynamic_findings"]) is how a static
    hit the DAST bridge *also* live-tested against its own route
    (scan_service.py's hybrid-scan correlation) gets its actual live_proof
    attached — the request that was sent, the payload, and (every check now
    populates this on every verdict, not just fail/confirmed) a real
    response/proof either way. static_only only goes False for confirmed/
    fail — a bridge PASS is still real live evidence (attach it, so a
    reader can see the route genuinely was attacked and didn't reproduce),
    but it doesn't upgrade the static finding into a proven one the way a
    fail/confirmed does. static_only stays True with no live_proof key at
    all when the bridge never reached this finding — a plain "SQL
    Injection" label with a code snippet is a real static finding, but not
    proof anyone attacked anything, and the evidence panel should say so.
    """
    item = {
        "file": v.get("location", {}).get("file"),
        "line": v.get("location", {}).get("start_line"),
        "note": v.get("type"),
        "code_snippet": (v.get("evidence") or {}).get("code_snippet"),
        "static_only": True,
        # Already computed by pipeline.py's _format_vulnerability
        # (_compute_cvss_score) — just never made it past the raw
        # vulnerability dict into the control-level evidence before.
        "severity": v.get("severity"),
        "confidence": v.get("confidence"),
        "cvss_score": v.get("cvss_score"),
        "cwe": v.get("cwe"),
    }
    dyn = (dynamic_by_static_id or {}).get(v.get("id"))
    if dyn:
        item["static_only"] = dyn.get("verdict") not in ("confirmed", "fail")
        item["live_proof"] = {
            "verdict": dyn.get("verdict"),
            "url": dyn.get("url"),
            "method": dyn.get("method"),
            "evidence_type": dyn.get("evidence_type"),
            "payload": dyn.get("payload"),
            "note": dyn.get("note"),
            "reproduction": dyn.get("reproduction"),
            "proof": dyn.get("proof"),
        }
    return item


def _dynamic_by_static_id(summary: dict) -> dict:
    """bridge_static_finding_id -> the DynamicFinding dict that live-tested
    it, for whichever one carries the strongest verdict when more than one
    bridge check touched the same static finding (CONFIRMED beats FAIL beats
    everything else, same ranking VERDICT_RANK uses elsewhere)."""
    _rank = {"confirmed": 3, "fail": 2, "inconclusive": 1}
    by_id: dict[str, dict] = {}
    for f in summary.get("dynamic_findings") or []:
        static_id = f.get("bridge_static_finding_id")
        if not static_id:
            continue
        current = by_id.get(static_id)
        if current is None or _rank.get(f.get("verdict"), 0) > _rank.get(current.get("verdict"), 0):
            by_id[static_id] = f
    return by_id


class ASVSService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self._control_rule_index: Optional[dict[str, list]] = None

    # ── Catalog ───────────────────────────────────────────────────────────────

    async def list_controls(self) -> list[dict]:
        cursor = self.db.asvs_controls.find({}, {"_id": 0}).sort("control_id", 1)
        return await cursor.to_list(length=None)

    async def get_control(self, control_id: str) -> Optional[dict]:
        return await self.db.asvs_controls.find_one({"control_id": control_id}, {"_id": 0})

    async def list_chapters(self) -> list[dict]:
        controls = await self.list_controls()
        by_chapter: dict[str, list[dict]] = defaultdict(list)
        for c in controls:
            by_chapter[c["chapter_id"]].append(c)

        chapters = []
        for chapter_id, chapter_controls in sorted(by_chapter.items(), key=lambda kv: int(kv[0][1:])):
            strategies = {c["detection_strategy"] for c in chapter_controls}
            chapters.append({
                "chapter_id": chapter_id,
                "title": chapter_controls[0]["chapter"].split(": ", 1)[-1],
                "detection_strategy": next(iter(strategies)) if len(strategies) == 1 else "mixed",
                "control_count": len(chapter_controls),
            })
        return chapters

    # ── Rule-catalog index (control_id -> rules), built once and cached ──────

    def _rule_index(self) -> dict[str, list]:
        if self._control_rule_index is None:
            index: dict[str, list] = defaultdict(list)
            for rule in get_query_store().get_all_queries():
                for control_id in rule.asvs_controls:
                    index[control_id].append(rule)
            self._control_rule_index = index
        return self._control_rule_index

    # ── Per-scan result computation ──────────────────────────────────────────

    async def build_results_for_scan(self, scan_id: str, user: Optional[dict] = None) -> dict[str, dict]:
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        summary = (scan or {}).get("summary") or {}
        attestation_user_id = str((scan or {}).get("user_id") or (user or {}).get("id") or "")

        attestations = {
            a["control_id"]: a async for a in self.db.attestations.find({
                "user_id": attestation_user_id,
                "scan_id": scan_id,
            })
        }

        controls = await self.list_controls()
        results: dict[str, dict] = {}
        for control in controls:
            results[control["control_id"]] = self._compute_result(control, summary, attestations, scan_id)

        if results:
            for control_id, result in results.items():
                await self.db.asvs_results.update_one(
                    {"scan_id": scan_id, "control_id": control_id},
                    {"$set": result},
                    upsert=True,
                )
        return results

    def _compute_result(self, control: dict, summary: dict, attestations: dict, scan_id: str) -> dict:
        control_id = control["control_id"]
        strategy = control["detection_strategy"]

        if strategy == "manual_attestation":
            if control_id in HYBRID_ATTESTATION_ELIGIBLE_CONTROLS:
                return self._merge_attestation_or_vulnerable_static(control_id, summary, attestations, scan_id)
            if control_id in HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS:
                return self._merge_attestation_or_dynamic_finding(control_id, summary, attestations, scan_id)
            if control_id in HYBRID_ATTESTATION_CAPABILITY_ELIGIBLE_CONTROLS:
                return self._merge_attestation_or_capability_finding(control_id, summary, attestations, scan_id)
            if control_id in HYBRID_ATTESTATION_DEPENDENCY_ELIGIBLE_CONTROLS:
                return self._merge_attestation_or_dependency_finding(control_id, summary, attestations, scan_id)
            return self._merge_attestation(control_id, attestations, scan_id)
        if strategy == "static_code":
            return self._merge_static(control_id, summary, scan_id)
        if strategy == "config_inspection":
            # V3.5.8: also accept a static rule-catalog match. V3.4.1 /
            # V13.4.6: also accept a live dynamic_probe result (DynamicProbe.
            # _check_hsts_header / _check_version_disclosure exist
            # specifically to cross-check these two — see their docstrings)
            # — see HYBRID_STATIC_ELIGIBLE_CONTROLS above.
            if control_id == "V3.5.8":
                return self._merge_config_or_compliant_static(control_id, summary, scan_id)
            if control_id in ("V3.4.1", "V13.4.6"):
                return self._merge_config_or_dynamic(control_id, summary, scan_id)
            return self._merge_config(control_id, summary, scan_id)
        if strategy == "dependency_scan":
            return self._merge_dependency(control_id, summary, scan_id)
        if strategy == "dynamic_probe":
            return self._merge_dynamic(control_id, summary, scan_id)
        return _not_tested(control_id, scan_id, reason="No detection strategy is configured for this control.")

    def _merge_config_or_compliant_static(self, control_id: str, summary: dict, scan_id: str) -> dict:
        static_matches = [
            v for v in (summary.get("vulnerabilities") or [])
            if control_id in (v.get("asvs_controls") or [])
            and v.get("asvs_finding_polarity") == "compliant"
        ]
        config_findings = [
            f for f in (summary.get("config_findings") or [])
            if f.get("control_id") == control_id
        ]

        passing_config = [f for f in config_findings if f.get("verdict") == "pass"]
        if passing_config or static_matches:
            evidence = [
                {"file": f.get("file"), "line": f.get("line"), "note": f.get("note"), "confidence": f.get("confidence")}
                for f in passing_config
            ] + [_evidence_from_vuln(v, _dynamic_by_static_id(summary)) for v in static_matches]
            confidence_values = [f.get("confidence") or 0 for f in passing_config] + [v.get("confidence") or 0 for v in static_matches]
            return {
                "control_id": control_id, "scan_id": scan_id, "verdict": "pass",
                "confidence": max(confidence_values, default=0.6), "evidence": evidence,
                "llm_explanation": None, "reviewed_by": None, "reviewed_at": None, "reason": None,
                # Real positive evidence either way: an explicit passing
                # config check, or a compliant-polarity marker that actually
                # matched something — never "swept and found nothing".
                "pass_basis": "confirmed", "fail_basis": None,
            }

        failing_config = [f for f in config_findings if f.get("verdict") == "fail"]
        if failing_config:
            evidence = [
                {"file": f.get("file"), "line": f.get("line"), "note": f.get("note"), "confidence": f.get("confidence")}
                for f in failing_config
            ]
            return {
                "control_id": control_id, "scan_id": scan_id, "verdict": "fail",
                "confidence": max((f.get("confidence") or 0 for f in failing_config), default=0.5),
                "evidence": evidence, "llm_explanation": None,
                "reviewed_by": None, "reviewed_at": None, "reason": None, "pass_basis": None,
                # A config check directly detected the failing condition —
                # deterministic, not an LLM guess needing confirmation.
                "fail_basis": "confirmed",
            }

        return _not_tested(
            control_id, scan_id,
            reason="No config finding and no compliant static-code marker were found for this control.",
        )

    def _merge_config_or_dynamic(self, control_id: str, summary: dict, scan_id: str) -> dict:
        # V13.4.6 has two independent sources of evidence: the static nginx
        # server_tokens reading and a live Server/X-Powered-By header probe.
        # Same fail-always-wins policy as the rest of this module.
        config_findings = [
            f for f in (summary.get("config_findings") or [])
            if f.get("control_id") == control_id
        ]
        probe_findings = [
            f for f in (summary.get("dynamic_probe_findings") or [])
            if f.get("control_id") == control_id
        ]

        failing = [f for f in config_findings if f.get("verdict") == "fail"] + \
            [f for f in probe_findings if f.get("verdict") == "fail"]
        if failing:
            evidence = [
                {"file": f.get("file"), "line": f.get("line"), "note": f.get("note"),
                 "severity": f.get("severity"), "confidence": f.get("confidence")}
                for f in failing
            ]
            return {
                "control_id": control_id, "scan_id": scan_id, "verdict": "fail",
                "confidence": max((f.get("confidence") or 0 for f in failing), default=0.5),
                "evidence": evidence, "llm_explanation": None,
                "reviewed_by": None, "reviewed_at": None, "reason": None, "pass_basis": None,
                # A config check or live probe directly detected the failing
                # condition — deterministic, not an LLM guess.
                "fail_basis": "confirmed",
            }

        passing = [f for f in config_findings if f.get("verdict") == "pass"] + \
            [f for f in probe_findings if f.get("verdict") == "pass"]
        if passing:
            evidence = [
                {"file": f.get("file"), "line": f.get("line"), "note": f.get("note"),
                 "severity": f.get("severity"), "confidence": f.get("confidence")}
                for f in passing
            ]
            return {
                "control_id": control_id, "scan_id": scan_id, "verdict": "pass",
                "confidence": max((f.get("confidence") or 0 for f in passing), default=0.5),
                "evidence": evidence, "llm_explanation": None,
                "reviewed_by": None, "reviewed_at": None, "reason": None,
                # A config check or live probe explicitly passed — direct
                # positive evidence, not an absence-based inference.
                "pass_basis": "confirmed", "fail_basis": None,
            }

        return _not_tested(
            control_id, scan_id,
            reason=(
                "No config finding and no live dynamic-probe result were found for this "
                "control — supply a target_url when starting the scan to enable the live check."
            ),
        )

    def _merge_attestation_or_vulnerable_static(
        self, control_id: str, summary: dict, attestations: dict, scan_id: str
    ) -> dict:
        """
        See HYBRID_ATTESTATION_ELIGIBLE_CONTROLS above. A confirmed
        DOUBLE_DECODE_CANONICALIZATION hit is real, independent evidence of
        a V1.1.1 violation and fails the control outright — same
        confirmed-hits-required policy _merge_static uses for every other
        vulnerable-polarity finding (an LLM-reviewed match, or a DAST bridge
        live reproduction; an unconfirmed static-only guess isn't treated as
        decisive here either, same as everywhere else in this module).
        No hit — confirmed or not — ever passes this control on its own;
        that falls through to the plain attestation path unchanged.
        """
        dyn_lookup = _dynamic_by_static_id(summary)
        hits = [
            v for v in (summary.get("vulnerabilities") or [])
            if control_id in (v.get("asvs_controls") or [])
            and v.get("asvs_finding_polarity", "vulnerable") != "compliant"
        ]
        if hits:
            def _explanation(v: dict) -> str | None:
                return (v.get("analysis", {}).get("llm_classification", {}) or {}).get("explanation")

            def _llm_confirmed(v: dict) -> bool:
                return _explanation(v) not in _UNCONFIRMED_LLM_MARKERS

            confirmed = [v for v in hits if _llm_confirmed(v) or v.get("bridge_confirmed")]
            if confirmed:
                worst = confirmed[0]
                return {
                    "control_id": control_id, "scan_id": scan_id, "verdict": "fail",
                    "confidence": worst.get("confidence"),
                    "evidence": [_evidence_from_vuln(v, dyn_lookup) for v in confirmed],
                    "llm_explanation": _explanation(worst), "reviewed_by": None, "reviewed_at": None,
                    "reason": None, "pass_basis": None,
                    "fail_basis": "confirmed",
                }
            # Unconfirmed static hit (LLM rate-limited/unavailable, no bridge
            # reproduction) — same as _merge_static's own "not decisive"
            # treatment, this isn't asserted as a fail. Falls through to
            # attestation, which a human needs to do anyway.
        return self._merge_attestation(control_id, attestations, scan_id)

    def _merge_attestation_or_dynamic_finding(
        self, control_id: str, summary: dict, attestations: dict, scan_id: str
    ) -> dict:
        """
        See HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS above. A FAIL/
        CONFIRMED live DAST finding (redirect_warning_probe.py for V3.7.3)
        is direct behavioral evidence — a real browser clicked an outbound
        link and observed where it actually went — and fails the control
        outright. Unlike _merge_attestation_or_vulnerable_static, there's no
        separate LLM-confirmation gate here: the DAST verdict already IS the
        confirmation (the probe drove a live interaction, it isn't a static
        pattern guess an LLM needs to weigh in on), so FAIL/CONFIRMED is
        decisive on its own. A PASS from the probe is deliberately never
        decisive either way (see the probe's own asymmetric-confidence
        design) — falls through to attestation, same as an unconfirmed
        static hit does in the sibling method above.
        """
        hits = [
            f for f in (summary.get("dynamic_findings") or [])
            if f.get("control_id") == control_id
        ]
        failing = [f for f in hits if f.get("verdict") in ("fail", "confirmed")]
        if failing:
            worst = failing[0]
            return {
                "control_id": control_id, "scan_id": scan_id, "verdict": "fail",
                "confidence": worst.get("confidence"),
                "evidence": [
                    {"note": f.get("note"), "severity": f.get("severity"), "confidence": f.get("confidence")}
                    for f in failing
                ],
                "llm_explanation": None, "reviewed_by": None, "reviewed_at": None,
                "reason": None, "pass_basis": None,
                "fail_basis": "confirmed",
            }
        return self._merge_attestation(control_id, attestations, scan_id)

    def _merge_attestation_or_capability_finding(
        self, control_id: str, summary: dict, attestations: dict, scan_id: str
    ) -> dict:
        """
        See HYBRID_ATTESTATION_CAPABILITY_ELIGIBLE_CONTROLS above.
        CapabilityChecker only ever emits a finding for a control once it has
        already found the relevant implementation (an SMS-OTP send call site,
        an IdP account-linking call) — it returns nothing at all, not a fail,
        when it finds no trace of the capability (see its own
        implemented=False handling), so every finding this reads is "found
        it, and judged it wrong," never "couldn't find it." A "fail"/
        "manual_review" verdict is therefore real, specific evidence and
        fails the control outright, same as a confirmed static/dynamic hit
        in the sibling methods above. A "pass" is deliberately never
        decisive on its own — these controls ask about validation/proof-of-
        ownership judgment calls a keyword-plus-LLM read can support but not
        fully close out, so a clean result still falls through to
        attestation.
        """
        hits = [
            f for f in (summary.get("capability_findings") or [])
            if f.get("control_id") == control_id
        ]
        failing = [f for f in hits if f.get("verdict") in ("fail", "manual_review")]
        if failing:
            worst = failing[0]
            return {
                "control_id": control_id, "scan_id": scan_id, "verdict": "fail",
                "confidence": worst.get("confidence"),
                "evidence": [
                    {"file": f.get("file"), "line": f.get("line"), "note": f.get("note")}
                    for f in failing
                ],
                "llm_explanation": worst.get("note"), "reviewed_by": None, "reviewed_at": None,
                "reason": None, "pass_basis": None,
                "fail_basis": "confirmed",
            }
        return self._merge_attestation(control_id, attestations, scan_id)

    # V17.2.6 — matches an OSV/CVE record naming BOTH a DTLS/ClientHello
    # handshake context and a race condition, not either alone: "race
    # condition" alone would false-match countless unrelated CVEs across
    # every ecosystem, and "ClientHello"/"DTLS" alone would false-match a
    # DTLS memory-safety bug that has nothing to do with the specific
    # race-during-handshake issue class this control asks about.
    _DTLS_CLIENTHELLO_RACE_HANDSHAKE_RE = re.compile(r"\b(clienthello|dtls)\b", re.IGNORECASE)
    _DTLS_CLIENTHELLO_RACE_CONCURRENCY_RE = re.compile(r"\brace(?:[\s-]?condition)?\b", re.IGNORECASE)

    def _merge_attestation_or_dependency_finding(
        self, control_id: str, summary: dict, attestations: dict, scan_id: str
    ) -> dict:
        """
        See HYBRID_ATTESTATION_DEPENDENCY_ELIGIBLE_CONTROLS above. Reads the
        SAME summary["dependency_findings"] list _merge_dependency already
        reads for V15.2.1 — every dependency's known-vulnerability record
        from OSV.dev, already fetched, not a new scan. Filters for a record
        whose vuln_id/summary text names both a DTLS/ClientHello handshake
        context and a race condition (see the two regexes above for why
        both are required, not either alone). A match is a real, published,
        specific CVE/advisory for exactly the vulnerability class this
        control asks about — decisive on its own, same as a confirmed
        static/dynamic/capability hit in the sibling methods above. No
        match only clears the "known-vulnerable-version" half of the
        control (its own wording keeps a live race-condition test as a
        fallback precisely because a clean OSV scan can't rule out an
        unpublished/0-day variant), so PASS still isn't decisive here.
        """
        matches = [
            f for f in (summary.get("dependency_findings") or [])
            if self._DTLS_CLIENTHELLO_RACE_HANDSHAKE_RE.search(f"{f.get('summary', '')} {f.get('vuln_id', '')}")
            and self._DTLS_CLIENTHELLO_RACE_CONCURRENCY_RE.search(f"{f.get('summary', '')} {f.get('vuln_id', '')}")
        ]
        if matches:
            worst = matches[0]
            return {
                "control_id": control_id, "scan_id": scan_id, "verdict": "fail",
                "confidence": 0.6,
                "evidence": [
                    {"note": f"{f['package']}@{f['version']} — {f['vuln_id']}: {f.get('summary', '')}"}
                    for f in matches
                ],
                "llm_explanation": (
                    f"{worst['package']}@{worst['version']} has a published advisory "
                    f"({worst['vuln_id']}) naming a DTLS/ClientHello race condition."
                ),
                "reviewed_by": None, "reviewed_at": None,
                "reason": None, "pass_basis": None,
                "fail_basis": "confirmed",
            }
        return self._merge_attestation(control_id, attestations, scan_id)

    async def list_manual_attestation_tasks(self, scan_id: str, user: Optional[dict] = None) -> dict:
        """
        Return the attestation page's scan-scoped work queue. This is not a
        global control catalog; every answer and proof reference belongs to
        this scan id.
        """
        results = await self.build_results_for_scan(scan_id, user=user)
        controls = await self.list_controls()
        scan = await self.db.scans.find_one({"scan_id": scan_id}) or {}
        user_id = str(scan.get("user_id") or (user or {}).get("id") or "")
        attestations = {
            a["control_id"]: a async for a in self.db.attestations.find({
                "user_id": user_id,
                "scan_id": scan_id,
            }, {"_id": 0})
        }

        tasks = []
        for control in controls:
            if control.get("detection_strategy") != "manual_attestation":
                continue
            result = results.get(control["control_id"], {})
            attestation = attestations.get(control["control_id"])
            decisive_scan_fail = (
                result.get("verdict") == "fail"
                and result.get("fail_basis") == "confirmed"
                and not attestation
            )
            tasks.append({
                "scan_id": scan_id,
                "control": control,
                "result": result,
                "attestation": attestation,
                "requires_attestation": not decisive_scan_fail,
                "status": "attested" if attestation else ("scan_failed" if decisive_scan_fail else "pending"),
                "process": {
                    "steps": _ATTESTATION_PROCESS,
                    "required_proof": _ATTESTATION_REQUIRED_PROOF,
                },
            })

        pending = sum(1 for t in tasks if t["status"] == "pending")
        answered = sum(1 for t in tasks if t["status"] == "attested")
        scan_failed = sum(1 for t in tasks if t["status"] == "scan_failed")
        return {
            "scan_id": scan_id,
            "scope": {
                "repo_id": scan.get("repo_id"),
                "branch": scan.get("branch"),
                "target_url": scan.get("target_url"),
                "created_at": scan.get("created_at"),
                "finished_at": scan.get("finished_at"),
            },
            "process": {
                "steps": _ATTESTATION_PROCESS,
                "required_proof": _ATTESTATION_REQUIRED_PROOF,
            },
            "counts": {
                "total": len(tasks),
                "pending": pending,
                "answered": answered,
                "scan_failed": scan_failed,
            },
            "attestations": attestations,
            "tasks": tasks,
        }

    def _merge_attestation(self, control_id: str, attestations: dict, scan_id: str) -> dict:
        att = attestations.get(control_id)
        if not att:
            return _not_tested(
                control_id, scan_id,
                reason="No manual attestation has been submitted for this control yet.",
            )
        evidence = []
        if att.get("evidence_url"):
            evidence.append({"note": att["evidence_url"]})
        if att.get("evidence_notes"):
            evidence.append({"note": att["evidence_notes"]})
        if att.get("proof_type"):
            evidence.append({"note": f"Proof type: {att['proof_type']}"})
        # An attestation with no evidence_url still has real, if minimal,
        # evidence: a specific named human made this determination at a
        # specific time — say so explicitly rather than leaving the panel
        # looking like nothing was ever recorded.
        reviewer = att.get("attested_by") or "a reviewer"
        reason = None if evidence else f"Manually attested by {reviewer}, but no supporting proof was provided."
        answer = att.get("answer", "not_tested")
        return {
            "control_id": control_id, "scan_id": scan_id,
            "verdict": answer,
            "confidence": None,
            "evidence": evidence,
            "llm_explanation": None,
            "reviewed_by": att.get("attested_by"),
            "reviewed_at": att.get("timestamp"),
            "reason": reason,
            # A human explicitly reviewed and answered — always "confirmed"
            # evidence, whether or not they attached a URL. Applies to
            # fail/manual_review the same as pass: a deliberate, backed
            # human judgment either way, not a low-confidence guess.
            "pass_basis": "confirmed" if answer == "pass" else None,
            "fail_basis": "confirmed" if answer in ("fail", "manual_review") else None,
        }

    @staticmethod
    def _dynamic_evidence_for_control(
        control_id: str, summary: dict, exclude_static_ids: Optional[set] = None,
    ) -> list[dict]:
        """Coarse dynamic corroboration for a static-backed control — every
        DAST finding tagged with this exact control_id, regardless of which
        route it came from, as opposed to _evidence_from_vuln's live_proof
        (only ever the ONE dynamic finding a static hit's own precise
        bridge_static_finding_id re-tested).

        Before this existed, a control's evidence could ONLY ever show the
        bridge-precise match: a static finding on route A with no dynamic
        finding re-testing route A specifically showed zero dynamic
        evidence, even when the DAST engine ran dozens of checks against
        this exact control on routes B, C, D and they're sitting right
        there in summary["dynamic_findings"] — e.g. BROKEN_ACCESS_CONTROL
        (V8.2.1/V8.2.2) flagged on one page with an LLM-unconfirmed static
        hit, while UNAUTHENTICATED_ACCESS_ALLOWED independently PASSED
        against six other routes in the same scan; the report showed only
        the former and completely hid the latter. Doesn't change any
        verdict (see the callers' own comments on why a clean PASS
        elsewhere in the app never overrides an unconfirmed/failing static
        hit on its own route) — this only makes evidence that already
        existed in the scan actually visible to the reader.

        exclude_static_ids skips bridge_static_finding_id-tagged findings
        already rendered via a per-vuln live_proof, so the same live result
        never appears twice in one control's evidence list.
        """
        exclude = exclude_static_ids or set()
        items = []
        for f in summary.get("dynamic_findings") or []:
            if f.get("control_id") != control_id:
                continue
            static_id = f.get("bridge_static_finding_id")
            if static_id and static_id in exclude:
                continue
            items.append({
                "note": f"Dynamic check — {f.get('rule_id', 'unknown rule')}",
                # Deliberately a different key from _evidence_from_vuln's
                # "live_proof" — that key means the bridge re-tested THIS
                # exact static finding's own route; this is a different
                # route that merely shares the control_id. Same verdict
                # word ("fail") means something weaker here (see
                # _evidence_flowables' _COARSE_DYNAMIC_LABEL), so it can't
                # reuse live_proof's "Confirmed — a live attack..." wording
                # without overstating what a cross-route correlation
                # actually proves.
                "dynamic_corroboration": {
                    "verdict": f.get("verdict"),
                    "url": f.get("url"),
                    "method": f.get("method"),
                    "evidence_type": f.get("evidence_type"),
                    "payload": f.get("payload"),
                    "note": f.get("note"),
                    "reproduction": f.get("reproduction"),
                    "proof": f.get("proof"),
                },
            })
        # _evidence_flowables truncates to a fixed per-control limit, so
        # without this a control with e.g. 25 "fail" checks (often the same
        # false-positive rule firing on every public page — see
        # UNAUTHENTICATED_ACCESS_ALLOWED's own docstring) and 6 "pass"
        # checks scattered later in scan order would show 12 fails and cut
        # off before a single pass — the exact case this whole method
        # exists to surface (see the class docstring's V8.2.1 example).
        # Sorting pass/confirmed first guarantees the truncated view still
        # shows both sides, not just whichever verdict happened to run
        # first during the scan.
        _verdict_priority = {"pass": 0, "confirmed": 1}
        items.sort(key=lambda it: _verdict_priority.get(it["dynamic_corroboration"]["verdict"], 2))
        return items

    def _merge_static(self, control_id: str, summary: dict, scan_id: str) -> dict:
        dyn_lookup = _dynamic_by_static_id(summary)
        # Capability-check controls (V6.2.2/.3/.4, V6.3.1, V6.4.1, V7.2.4, V7.4.1/.2,
        # V14.3.1) have their own side-channel finding — see CapabilityChecker. It never
        # goes through the vulnerability slice/classifier pipeline (which would silently
        # discard "this isn't a vulnerability" verdicts), so check it first. Falls through
        # to the logic below, unchanged, for every other control or if it found nothing.
        for cap in summary.get("capability_findings") or []:
            if cap.get("control_id") == control_id:
                cap_verdict = cap.get("verdict", "not_tested")
                return {
                    "control_id": control_id, "scan_id": scan_id,
                    "verdict": cap_verdict,
                    "confidence": cap.get("confidence"),
                    "evidence": [{"file": cap.get("file"), "line": cap.get("line"), "note": cap.get("note")}] if cap.get("file") else [],
                    "llm_explanation": cap.get("note"),
                    "reviewed_by": None, "reviewed_at": None,
                    "reason": cap.get("note") if cap_verdict == "not_tested" else None,
                    # CapabilityChecker inspects specific code shapes directly
                    # (a concrete file/line when one exists) — real positive
                    # evidence either way, never an absence-based sweep or an
                    # unconfirmed guess.
                    "pass_basis": "confirmed" if cap_verdict == "pass" else None,
                    "fail_basis": "confirmed" if cap_verdict in ("fail", "manual_review") else None,
                }

        vulns = summary.get("vulnerabilities") or []
        matches = [v for v in vulns if control_id in (v.get("asvs_controls") or [])]

        if matches:
            vulnerable_hits = [v for v in matches if v.get("asvs_finding_polarity", "vulnerable") != "compliant"]
            if vulnerable_hits:
                def _explanation(v: dict) -> str | None:
                    return (v.get("analysis", {}).get("llm_classification", {}) or {}).get("explanation")

                def _llm_confirmed(v: dict) -> bool:
                    return _explanation(v) not in _UNCONFIRMED_LLM_MARKERS

                # A hit counts as confirmed if EITHER an LLM actually reviewed
                # and confirmed it, OR the DAST bridge (app/domain/analysis/
                # dast/bridge.py, via scan_service.py's hybrid-scan
                # correlation) live-reproduced this *exact* static finding
                # against its own route (bridge_confirmed) — that's direct,
                # independent evidence of exploitability, not weaker than an
                # LLM's static-only judgment call. Plain dynamic_confirmed
                # (coarse: some dynamic finding merely shares this control,
                # not proven to be the same route) does NOT count here —
                # only the precise, bridge_confirmed tier does.
                confirmed_hits = [v for v in vulnerable_hits if _llm_confirmed(v) or v.get("bridge_confirmed")]
                # If every hit is an unconfirmed static-only fallback (no LLM
                # review AND no live bridge reproduction), that's a guess the
                # tool couldn't verify, not a confident failure — surface it
                # for a human to review instead of asserting something we're
                # not actually sure of.
                decisive_hits = confirmed_hits or vulnerable_hits
                verdict = "fail" if confirmed_hits else "manual_review"
                worst = decisive_hits[0]
                evidence = [_evidence_from_vuln(v, dyn_lookup) for v in decisive_hits]
                evidence += self._dynamic_evidence_for_control(
                    control_id, summary, exclude_static_ids={v.get("id") for v in decisive_hits},
                )
                if verdict == "manual_review":
                    explanation = (
                        f"{len(vulnerable_hits)} potential finding(s) matched a static pattern, but the LLM "
                        "could not confirm them (rate-limited/unavailable during this scan). Needs human review."
                    )
                elif worst.get("bridge_confirmed") and not _llm_confirmed(worst):
                    # The LLM never actually reviewed this one (rate-limited/
                    # unavailable), but the dynamic bridge independently
                    # reproduced the exploit live against the exact same
                    # route — don't show the stale "LLM unavailable" fallback
                    # text alongside a "fail" verdict, that reads as a
                    # contradiction.
                    explanation = (
                        "The LLM could not confirm this statically (rate-limited/unavailable during this "
                        "scan), but the dynamic scan independently reproduced the exploit live against the "
                        "exact same route (see the DAST findings section) — direct evidence, not a guess."
                    )
                else:
                    explanation = _explanation(worst)
                return {
                    "control_id": control_id, "scan_id": scan_id, "verdict": verdict,
                    "confidence": worst.get("confidence"), "evidence": evidence,
                    "llm_explanation": explanation, "reviewed_by": None, "reviewed_at": None,
                    "reason": None, "pass_basis": None,
                    # The one genuinely weak-evidence case in this whole
                    # module: "manual_review" here means an LLM never got to
                    # confirm the static pattern match at all (rate-limited/
                    # unavailable) — a real pattern hit, but nobody actually
                    # verified it's a true positive. "fail" only ever
                    # reaches this branch when confirmed_hits is non-empty,
                    # i.e. an LLM did review and confirm it.
                    "fail_basis": "confirmed" if verdict == "fail" else "unconfirmed",
                }
            # Only compliant-polarity (marker) findings matched -> positive evidence
            best = matches[0]
            evidence = [_evidence_from_vuln(v, dyn_lookup) for v in matches]
            evidence += self._dynamic_evidence_for_control(
                control_id, summary, exclude_static_ids={v.get("id") for v in matches},
            )
            return {
                "control_id": control_id, "scan_id": scan_id, "verdict": "pass",
                "confidence": best.get("confidence"), "evidence": evidence,
                "llm_explanation": None, "reviewed_by": None, "reviewed_at": None,
                "reason": None,
                # A compliant-polarity marker actually matched something —
                # direct positive evidence, not an absence-based inference.
                "pass_basis": "confirmed", "fail_basis": None,
            }

        # No findings at all — distinguish "ran and found nothing" from "only a
        # weak marker rule exists for this control and it didn't fire".
        if not summary:
            return _not_tested(
                control_id, scan_id,
                reason="This scan has not produced a results summary yet (still running, or failed before completing).",
            )
        # Zero matches only means "ran across the repo and found nothing" if
        # the static engine actually had source to run against. scan_type=
        # "dynamic" runs (see _run_dynamic_scan) set total_files/files_scanned
        # to 0 explicitly — no code was ever submitted, only a live URL was
        # probed — so an empty vulnerabilities list there means "never
        # searched", not "searched and clean". Falling through to pass-by-
        # absence in that case would award every rule-covered static control
        # an unearned pass regardless of what the code actually contains.
        if not summary.get("total_files"):
            return _not_tested(
                control_id, scan_id,
                reason=(
                    "No static code analysis ran for this scan (dynamic-only scan, or no "
                    "source was provided) — this control needs a code-backed scan to evaluate."
                ),
            )
        rules = self._rule_index().get(control_id, [])
        # No rule covers this control at all (e.g. it's exclusively handled by
        # CapabilityChecker and found no evidence either way) — nothing actually ran,
        # so this must stay not_tested rather than falling through to an unearned pass.
        if not rules or all(r.finding_polarity == "compliant" for r in rules):
            return _not_tested(
                control_id, scan_id,
                reason=(
                    "This control is only covered by a weak presence-marker rule (or by no "
                    "rule at all) — its absence in the scan isn't proof the control is "
                    "satisfied, so it can't be confidently marked pass or fail."
                ),
            )
        # "Pass by absence": every rule tagged for this control ran across
        # the whole repo and matched nothing — a real result, just with no
        # single file/line to point at (there's nothing to flag). Name the
        # rule(s) that actually ran and how much code they ran across so
        # this reads as "evaluated, passed" rather than "not evaluated" —
        # applies live to every past and future scan (compliance results
        # are recomputed from the stored scan summary on every view, never
        # cached at scan time), not just newly-run ones.
        rule_names = sorted({r.name for r in rules})
        files_scanned = summary.get("files_scanned") or summary.get("total_files")
        coverage = f" across {files_scanned} scanned file(s)" if files_scanned else ""
        rule_list = ", ".join(rule_names) if len(rule_names) <= 3 else f"{len(rule_names)} rules"
        reason = (
            f"Evaluated by {rule_list}{coverage} — no matching pattern was found, "
            f"which is a pass for this control."
        )
        return {
            "control_id": control_id, "scan_id": scan_id, "verdict": "pass",
            "confidence": 0.6, "evidence": self._dynamic_evidence_for_control(control_id, summary),
            "llm_explanation": "Static analysis ran across the scanned repository and found no violation of this control.",
            "reviewed_by": None, "reviewed_at": None, "reason": reason,
            # The defining "no_findings" case: a rule that actively searches
            # for the bad pattern ran across the whole repo and matched
            # nothing. Real signal, but not the same strength as a positive
            # marker match, a passing config/probe check, or a human
            # attestation — surfaced separately so "PASS" doesn't imply more
            # confidence than a pattern-not-found result actually earns.
            "pass_basis": "no_findings", "fail_basis": None,
        }

    def _merge_config(self, control_id: str, summary: dict, scan_id: str) -> dict:
        findings = [f for f in (summary.get("config_findings") or []) if f.get("control_id") == control_id]
        if not findings:
            return _not_tested(
                control_id, scan_id,
                reason=(
                    "No configuration file relevant to this control (e.g. nginx.conf, "
                    "docker-compose.yml, a CSP/security-headers config) was found in the "
                    "scanned repository."
                ),
            )

        failing = [f for f in findings if f.get("verdict") == "fail"]
        chosen = failing or findings
        verdict = "fail" if failing else ("pass" if any(f.get("verdict") == "pass" for f in findings) else "not_tested")
        evidence = [
            {"file": f.get("file"), "line": f.get("line"), "note": f.get("note"), "confidence": f.get("confidence")}
            for f in chosen
        ]
        confidence = max((f.get("confidence") or 0 for f in chosen), default=None)
        reason = (
            "Config findings were recorded for this control, but none had a definitive "
            "pass or fail verdict."
        ) if verdict == "not_tested" else None
        return {
            "control_id": control_id, "scan_id": scan_id, "verdict": verdict,
            "confidence": confidence, "evidence": evidence,
            "llm_explanation": None, "reviewed_by": None, "reviewed_at": None,
            "reason": reason,
            # An explicit passing/failing config finding (e.g. a security
            # header was read and found correctly/incorrectly configured) —
            # direct evidence either way, not an absence-based inference or
            # an unconfirmed guess.
            "pass_basis": "confirmed" if verdict == "pass" else None,
            "fail_basis": "confirmed" if verdict == "fail" else None,
        }

    def _merge_dependency(self, control_id: str, summary: dict, scan_id: str) -> dict:
        if control_id != "V15.2.1":
            return _not_tested(
                control_id, scan_id,
                reason="Dependency-scan detection currently only evaluates control V15.2.1.",
            )
        control_result = summary.get("dependency_control_result")
        if not control_result:
            return _not_tested(
                control_id, scan_id,
                reason=(
                    "The dependency/SBOM scan did not produce a result for this scan — it may "
                    "not have run, or no dependency manifest files (requirements.txt, "
                    "package.json, etc.) could be found or parsed."
                ),
            )

        dep_findings = summary.get("dependency_findings") or []

        def _dep_evidence(f: dict) -> dict:
            # cve_details is populated by DependencyScanner.enrich_with_nvd —
            # real NVD-sourced CVSS, not fabricated. A finding can alias
            # several CVEs (one GHSA advisory covering multiple CVE IDs);
            # the highest score across them is the one that matters for risk.
            cve_details = f.get("cve_details") or []
            scores = [d.get("cvss_score") for d in cve_details if d.get("cvss_score") is not None]
            return {
                "note": f"{f['package']}@{f['version']} — {f['vuln_id']} ({f['severity']})",
                "severity": f.get("severity"),
                "cvss_score": max(scores) if scores else None,
            }

        evidence = [_dep_evidence(f) for f in dep_findings[:20]]
        dep_verdict = control_result.get("verdict", "not_tested")
        # A pass with no dep_findings ("no vulnerable dependencies found")
        # has no evidence[] entries either — surface control_result's own
        # note (already accurate/specific, e.g. "No known-vulnerable
        # dependencies found against OSV.dev.") as `reason` too, not just
        # `llm_explanation`, so the evidence panel shows it directly instead
        # of falling back to a generic message.
        # Two different shapes of "pass" here: vulnerable dependencies were
        # found but all are still within their SLA remediation window (real,
        # specific evidence — "confirmed"), vs. no vulnerable dependencies
        # were found at all against OSV.dev (an absence-based claim, same
        # epistemic weight as the static "swept and found nothing" case —
        # "no_findings", since a dependency simply not being in that
        # database isn't proof it's actually safe).
        pass_basis = None
        if dep_verdict == "pass":
            pass_basis = "confirmed" if evidence else "no_findings"
        # fail/manual_review here always have real evidence backing them —
        # a specific CVE matched against a specific package version, never
        # an unconfirmed guess (unlike the static-taint LLM-unavailable
        # case) — "manual_review" just means the policy question (is being
        # within the SLA window acceptable) needs a human, not that the
        # finding itself is in doubt.
        fail_basis = "confirmed" if dep_verdict in ("fail", "manual_review") else None
        return {
            "control_id": control_id, "scan_id": scan_id,
            "verdict": dep_verdict,
            "confidence": 0.75 if dep_findings else 0.9,
            "evidence": evidence,
            "llm_explanation": control_result.get("note"),
            "reviewed_by": None, "reviewed_at": None,
            "reason": control_result.get("note") if not evidence else None,
            "pass_basis": pass_basis, "fail_basis": fail_basis,
        }

    def _merge_dynamic(self, control_id: str, summary: dict, scan_id: str) -> dict:
        findings = [f for f in (summary.get("dynamic_probe_findings") or []) if f.get("control_id") == control_id]
        if not findings:
            return _not_tested(
                control_id, scan_id,
                reason=(
                    "No live dynamic-probe result was recorded for this control — supply a "
                    "target_url when starting the scan to enable live checks."
                ),
            )
        f = findings[0]
        probe_verdict = f.get("verdict", "not_tested")
        return {
            "control_id": control_id, "scan_id": scan_id, "verdict": probe_verdict,
            "confidence": f.get("confidence"),
            "evidence": [{"note": f.get("note"), "severity": f.get("severity"), "confidence": f.get("confidence")}],
            "llm_explanation": None, "reviewed_by": None, "reviewed_at": None,
            "reason": f.get("note") if probe_verdict == "not_tested" else None,
            # A live probe directly checked something concrete (TLS version,
            # a security header, .git exposure, ...) and got a definite
            # result either way — real evidence, not an inference from
            # absence or an unconfirmed guess.
            "pass_basis": "confirmed" if probe_verdict == "pass" else None,
            "fail_basis": "confirmed" if probe_verdict in ("fail", "manual_review") else None,
        }

    # ── Aggregation for the compliance summary ───────────────────────────────

    async def get_compliance_summary(self, scan_id: str, user: Optional[dict] = None) -> dict:
        results = await self.build_results_for_scan(scan_id, user=user)
        controls = await self.list_controls()

        by_chapter: dict[str, list[dict]] = defaultdict(list)
        for c in controls:
            by_chapter[c["chapter_id"]].append(c)

        chapters = []
        for chapter_id, chapter_controls in sorted(by_chapter.items(), key=lambda kv: int(kv[0][1:])):
            counts = {k: 0 for k in _VERDICT_KEYS}
            for c in chapter_controls:
                verdict = results.get(c["control_id"], {}).get("verdict", "not_tested")
                counts[verdict] = counts.get(verdict, 0) + 1
            strategies = {c["detection_strategy"] for c in chapter_controls}
            chapters.append({
                "chapter_id": chapter_id,
                "title": chapter_controls[0]["chapter"].split(": ", 1)[-1],
                "detection_strategy": next(iter(strategies)) if len(strategies) == 1 else "mixed",
                "control_count": len(chapter_controls),
                "counts": counts,
            })

        levels: dict[str, dict] = {}
        for level in ASVS_LEVELS:
            applicable = [c for c in controls if _level_includes(c["level"], level)]
            passed = [c for c in applicable if results.get(c["control_id"], {}).get("verdict") == "pass"]
            total = len(applicable)
            levels[level] = {
                "total": total, "passed": len(passed),
                "pct": round(len(passed) / total * 100) if total else 0,
            }

        # "Overall" — every control in the catalog counted exactly once, no
        # level filtering at all (unlike L1/L2/L3 above, which each apply
        # _level_includes and so double-count a control that's shared
        # across levels). Not simply an alias for L3's number even though
        # they happen to coincide today (L3 is currently the broadest
        # level and _level_includes makes its applicable set the full
        # catalog) — if the catalog ever grows a level higher than L3, or a
        # control with a level string _level_includes can't place in any
        # of L1/L2/L3, this still reflects the true whole-catalog score
        # rather than silently drifting from L3's.
        passed_overall = sum(1 for c in controls if results.get(c["control_id"], {}).get("verdict") == "pass")
        total_overall = len(controls)
        levels["overall"] = {
            "total": total_overall, "passed": passed_overall,
            "pct": round(passed_overall / total_overall * 100) if total_overall else 0,
        }

        return {
            "scan_id": scan_id,
            "chapters": chapters,
            "levels": levels,
            "results": results,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── Portfolio dashboard (cross-repo aggregation) ─────────────────────────

    async def get_portfolio_dashboard(self, trend_length: int = 8, user: Optional[dict] = None) -> dict:
        """
        Cross-repo compliance view: for every repo with at least one completed
        scan, its latest compliance snapshot plus a short history for a trend
        line; portfolio-wide attestation coverage; and the controls failing
        across the most repos (cross-repo risk ranking). Repo names are not
        resolved here (this service only holds the Mongo handle) — the route
        layer joins them in from the SQL repositories table.
        """
        controls = await self.list_controls()
        controls_by_id = {c["control_id"]: c for c in controls}
        total_manual = sum(1 for c in controls if c["detection_strategy"] == "manual_attestation")
        attestation_query = {}
        scan_query: dict[str, Any] = {"state": "COMPLETED"}
        if user and user.get("role") != UserRole.ADMIN.value:
            user_oid = to_object_id(user.get("id", ""))
            values: list[Any] = [str(user.get("id"))]
            if user_oid:
                values.append(user_oid)
            scan_query["user_id"] = {"$in": values}
            attestation_query = {"user_id": user.get("id")}
        answered = await self.db.attestations.count_documents(attestation_query)

        cursor = self.db.scans.find(
            scan_query,
            {"scan_id": 1, "repo_id": 1, "created_at": 1, "finished_at": 1},
        ).sort("created_at", -1)
        scans = await cursor.to_list(length=None)

        by_repo: dict[Any, list[dict]] = defaultdict(list)
        for s in scans:
            by_repo[s.get("repo_id")].append(s)

        # get_compliance_summary is the expensive part here (per-control
        # verdict computation over the full ASVS catalog) — with one repo
        # per portfolio entry and up to trend_length scans each, awaiting
        # them one at a time made this endpoint O(repos * trend_length)
        # *sequential* round-trips. Measured at ~0.3-0.4s/call, 11 repos x
        # up to 8 trend scans was 25s+ and climbing with scan history — the
        # actual timeout that stalled the repositories page (Promise.
        # allSettled on the frontend waits for every request, portfolio
        # dashboard included, before "Loading repositories..." clears).
        # Every (repo, scan) pair's summary is independent of every other,
        # so gathering them concurrently changes only wall-clock time, not
        # the result: same summaries, same trend order, same totals.
        scan_ids_needed: dict[str, None] = {}
        for repo_scans in by_repo.values():
            latest_id = repo_scans[0]["scan_id"]
            for s in reversed(repo_scans[:trend_length]):
                scan_ids_needed[s["scan_id"]] = None
            scan_ids_needed[latest_id] = None
        unique_scan_ids = list(scan_ids_needed)
        summaries_list = await asyncio.gather(
            *(self.get_compliance_summary(sid, user=user) for sid in unique_scan_ids)
        )
        summary_by_scan_id = dict(zip(unique_scan_ids, summaries_list))

        fail_counter: dict[str, int] = defaultdict(int)
        # Real cross-repo chapter compliance: each repo's latest scan already
        # carries a full chapter breakdown (built below as latest_summary) —
        # summing those counts across every scanned repo turns it into an
        # actual portfolio aggregate instead of one repo's snapshot standing
        # in for all of them.
        chapter_totals: dict[str, dict] = {}
        repos_out = []
        for repo_id, repo_scans in by_repo.items():
            latest = repo_scans[0]
            trend_scans = list(reversed(repo_scans[:trend_length]))

            trend = []
            latest_summary = None
            for s in trend_scans:
                s_summary = summary_by_scan_id[s["scan_id"]]
                trend.append({
                    "scan_id": s["scan_id"],
                    "created_at": s.get("created_at"),
                    # Bug fix — "pct" here fed both the per-repo sparkline
                    # (Repository Health card, deliberately L1-scoped, not
                    # labeled "Compliance") AND "Portfolio Compliance
                    # Trend"/overall_avg_pct below (both explicitly labeled
                    # "Compliance", which everywhere else in the app now
                    # means the whole-catalog figure — see ScanPage/
                    # AttestationPage's own bug-fix comments). One L1-only
                    # number silently backing two differently-scoped labels
                    # is exactly that bug. Kept as "pct" (unchanged key/
                    # meaning, still L1) for the Health-card consumers;
                    # "overall_pct" added alongside it for the
                    # Compliance-labeled consumers instead of repurposing
                    # the existing key and breaking the Health card.
                    "pct": s_summary["levels"]["L1"]["pct"],
                    "overall_pct": s_summary["levels"]["overall"]["pct"],
                })
                if s["scan_id"] == latest["scan_id"]:
                    latest_summary = s_summary
            if latest_summary is None:
                latest_summary = summary_by_scan_id[latest["scan_id"]]

            l1 = latest_summary["levels"]["L1"]
            overall = latest_summary["levels"]["overall"]
            fails = [r for r in latest_summary["results"].values() if r["verdict"] == "fail"]
            not_tested = sum(1 for r in latest_summary["results"].values() if r["verdict"] == "not_tested")
            for r in fails:
                fail_counter[r["control_id"]] += 1

            for ch in latest_summary["chapters"]:
                agg = chapter_totals.get(ch["chapter_id"])
                if agg is None:
                    agg = {
                        "chapter_id": ch["chapter_id"],
                        "title": ch["title"],
                        "control_count": ch["control_count"],
                        "counts": defaultdict(int),
                        "repo_count": 0,
                    }
                    chapter_totals[ch["chapter_id"]] = agg
                agg["repo_count"] += 1
                for verdict, n in ch["counts"].items():
                    agg["counts"][verdict] += n

            repos_out.append({
                "repo_id": repo_id,
                "latest_scan_id": latest["scan_id"],
                "latest_scan_at": latest.get("created_at"),
                "scan_count": len(repo_scans),
                "l1_pct": l1["pct"],
                "passed": l1["passed"],
                "total": l1["total"],
                # Whole-catalog figures alongside the pre-existing L1-only
                # ones above — added, not substituted, so callers that
                # deliberately want L1 (Repository Health's threshold/
                # sparkline, not labeled "Compliance") keep working
                # unchanged. Every place actually labeled "Compliance"
                # (RepoIntegrationPage's ring/table column) should read
                # these instead — see the trend-block comment above for
                # the full history of this split.
                "overall_pct": overall["pct"],
                "overall_passed": overall["passed"],
                "overall_total": overall["total"],
                "fail_count": len(fails),
                "not_tested_count": not_tested,
                "trend": trend,
            })

        repos_out.sort(key=lambda r: r["l1_pct"])

        # Real portfolio-wide trend: walk every repo's scan events in actual
        # chronological order and, at each event, average each repo's most
        # recently *known* pct (carrying forward repos that haven't scanned
        # again yet). Averaging trend[i] across repos by array index instead
        # would silently mix together scans from unrelated dates — a repo's
        # 1st-ever scan getting averaged against another repo's 8th — and
        # once a repo runs out of history the average quietly drops to
        # whichever repos are left, producing a fake trailing dip that has
        # nothing to do with compliance actually changing.
        # overall_pct (whole-catalog), not pct (L1) — this trend feeds
        # "Portfolio Compliance Trend" on the dashboard, labeled
        # "Compliance" with no L1 qualifier, same scope every other
        # Compliance-labeled figure in the app now uses.
        trend_events = sorted(
            (
                (pt["created_at"], r["repo_id"], pt["overall_pct"])
                for r in repos_out
                for pt in r["trend"]
            ),
            key=lambda e: e[0] or datetime.min,
        )
        last_known: dict[Any, float] = {}
        by_day: dict[Any, dict] = {}
        for created_at, repo_id, pct in trend_events:
            last_known[repo_id] = pct
            # Collapse same-day events to one point (the day's final known
            # state) — several repos scanning within the same day would
            # otherwise plot as several near-vertical jumps for no reason.
            day_key = created_at.date() if hasattr(created_at, "date") else created_at
            by_day[day_key] = {
                "date": created_at,
                "pct": round(sum(last_known.values()) / len(last_known)),
            }
        portfolio_trend = list(by_day.values())

        top_failing = sorted(fail_counter.items(), key=lambda kv: kv[1], reverse=True)[:5]
        top_failing_out = []
        for control_id, repo_fail_count in top_failing:
            c = controls_by_id.get(control_id, {})
            top_failing_out.append({
                "control_id": control_id,
                "description": c.get("description", ""),
                "chapter_id": c.get("chapter_id", ""),
                "level": c.get("level", ""),
                "repo_fail_count": repo_fail_count,
            })

        # Bug fix — this averaged r["l1_pct"] despite being named
        # overall_avg_pct and consumed as a portfolio-wide "Compliance
        # Score" fallback (AnalyticsPage.js) — a whole-catalog-sounding
        # name silently returning the L1-only average, same mismatch class
        # documented on repos_out/trend above. Now actually averages the
        # whole-catalog figure the name says it does.
        overall_avg_pct = round(sum(r["overall_pct"] for r in repos_out) / len(repos_out)) if repos_out else 0
        total_open_fails = sum(r["fail_count"] for r in repos_out)

        chapters_out = []
        for ch in sorted(chapter_totals.values(), key=lambda c: int(c["chapter_id"][1:])):
            total_applicable = ch["control_count"] * ch["repo_count"]
            passed = ch["counts"].get("pass", 0)
            chapters_out.append({
                "chapter_id": ch["chapter_id"],
                "title": ch["title"],
                "control_count": ch["control_count"],
                "repo_count": ch["repo_count"],
                "counts": dict(ch["counts"]),
                "pct": round(passed / total_applicable * 100) if total_applicable else 0,
            })

        return {
            "repos": repos_out,
            "overall_avg_pct": overall_avg_pct,
            "repo_count": len(repos_out),
            "total_open_fails": total_open_fails,
            "attestation_coverage": {
                "answered": answered,
                "total": total_manual,
                "pct": round(answered / total_manual * 100) if total_manual else 0,
            },
            "top_failing_controls": top_failing_out,
            # Real portfolio-wide chapter breakdown — pass/fail counts summed
            # from every scanned repo's latest scan, not one repo's snapshot
            # mislabeled as the aggregate.
            "chapters": chapters_out,
            # Real portfolio-wide compliance trend, in chronological order —
            # see the trend_events comment above for why this replaces
            # naive by-index averaging of each repo's trend array.
            "portfolio_trend": portfolio_trend,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── Executive summary (GPT-4o via GitHub Models, with deterministic fallback) ──

    def _fallback_executive_summary(self, summary: dict, failing: list[dict], not_tested: list[dict]) -> str:
        overall = summary["levels"].get("overall", summary["levels"].get("L3", {}))
        total = overall.get("total", 0)
        worst_chapters = sorted(
            (ch for ch in summary["chapters"] if ch["counts"].get("fail", 0) > 0),
            key=lambda ch: ch["counts"]["fail"], reverse=True,
        )[:3]
        worst_text = ", ".join(f"{ch['chapter_id']} ({ch['title']})" for ch in worst_chapters) or "none"
        return (
            f"This assessment evaluated {total} OWASP ASVS 5.0.0 requirements across the full catalog. "
            f"{overall.get('passed', 0)} of {total} controls ({overall.get('pct', 0)}%) currently pass "
            f"verification. {len(failing)} control(s) failed and require remediation, and "
            f"{len(not_tested)} control(s) have not yet been verified, pending a scan or manual "
            f"attestation. The chapters with the most failing controls are: {worst_text}. "
            f"Review the failing-controls section below for supporting evidence and prioritize "
            f"remediation accordingly before re-scanning to confirm closure."
        )

    async def _generate_executive_summary(self, summary: dict) -> str:
        failing = [r for r in summary["results"].values() if r["verdict"] == "fail"]
        not_tested = [r for r in summary["results"].values() if r["verdict"] == "not_tested"]
        fallback = self._fallback_executive_summary(summary, failing, not_tested)

        pool = _get_report_pool()
        if not pool.is_available:
            return fallback

        overall = summary["levels"].get("overall", summary["levels"].get("L3", {}))
        chapter_lines = "\n".join(
            f"- {ch['chapter_id']} {ch['title']}: {ch['counts'].get('pass', 0)} pass / "
            f"{ch['counts'].get('fail', 0)} fail / {ch['counts'].get('not_tested', 0)} not tested "
            f"(of {ch['control_count']} controls)"
            for ch in summary["chapters"]
        )
        fail_lines = "\n".join(
            f"- {r['control_id']}: {(r.get('llm_explanation') or (r.get('evidence') or [{}])[0].get('note') or 'failed check')}"
            for r in failing[:15]
        ) or "None"

        prompt = (
            f"Scan ID: {summary.get('scan_id')}\n"
            f"Overall ASVS completion: {overall.get('passed', 0)}/{overall.get('total', 0)} ({overall.get('pct', 0)}%)\n\n"
            f"Chapter breakdown:\n{chapter_lines}\n\n"
            f"Failing controls ({len(failing)} total, showing up to 15):\n{fail_lines}\n\n"
            f"Not-tested controls (no automated or manual verdict yet): {len(not_tested)}\n\n"
            "Write the executive summary now."
        )

        try:
            raw = await pool.call(messages=[{"role": "user", "content": prompt}], max_tokens=500, temperature=0.3)
        except Exception:
            logger.exception("Executive summary generation failed; using deterministic fallback")
            raw = None
        return raw.strip() if raw else fallback

    @staticmethod
    def _methodology_paragraphs(control_count: int = 70) -> list[str]:
        return [
            f"Each of the {control_count} requirements is assigned one of five detection strategies, "
            "chosen for how that specific requirement can actually be verified:",
            "<b>Static code analysis</b> — an AST/CFG/DFG taint engine traces untrusted "
            "input through the codebase against a catalog of vulnerability patterns; "
            "candidate findings are then reviewed by a large language model to confirm "
            "the verdict and explain the risk in plain language.",
            "<b>Configuration inspection</b> — parses environment files, YAML, Dockerfiles, "
            "and web-server configs for the relevant security setting (cookie flags, CORS, "
            "security headers, etc.).",
            "<b>Dependency scanning</b> — cross-references the project's declared dependencies "
            "against the OSV.dev vulnerability database and evaluates them against the "
            "organization's remediation SLA.",
            "<b>Dynamic probing</b> — connects to a live target URL (when supplied) to check "
            "TLS configuration, HSTS, and public exposure of sensitive paths.",
            "<b>Manual attestation</b> — requirements that describe documentation, process, or "
            "architectural decisions cannot be verified by tooling; these are answered "
            "directly by a reviewer, with optional evidence attached.",
            "A control is marked <b>not tested</b> whenever none of the above could reach a "
            "conclusive verdict — most commonly because no scan or attestation has been "
            "submitted for it yet, not because it was checked and found acceptable. Where a "
            "control has evidence from more than one source, a failing verdict always takes "
            "precedence.",
        ]

    # ── PDF export ────────────────────────────────────────────────────────────

    _LIVE_PROOF_LABEL = {
        "confirmed": "Confirmed — the scan reproduced real impact against the live target",
        "fail": "Confirmed — a live attack against the target produced this result",
        "pass": "Tested live — the attack did not reproduce against the target",
    }

    # Deliberately weaker wording than _LIVE_PROOF_LABEL above — these
    # render dynamic_corroboration items (a DIFFERENT route than the static
    # finding, only sharing its control_id, from
    # _dynamic_evidence_for_control), never the bridge-precise live_proof
    # ("this exact route was re-tested"). A coarse "fail" here means some
    # OTHER route flagged the same control, not that this specific static
    # finding's own route was attacked — reusing _LIVE_PROOF_LABEL's
    # "Confirmed — a live attack..." text would overstate that.
    _COARSE_DYNAMIC_LABEL = {
        "confirmed": "Corroborating — a different route flagged for this control: impact reproduced there",
        "fail": "Corroborating — a different route flagged for this control (not this exact finding's route)",
        "pass": "Corroborating — a different route was tested for this control and passed",
    }

    @staticmethod
    def _evidence_flowables(evidence: list[dict], cell_style, code_style, limit: int = 4) -> list:
        """One or more flowables per evidence item — location, CVSS/severity/
        confidence (whichever the detection strategy actually produced, see
        _evidence_from_vuln / _merge_* above), the note, a code snippet for
        static findings, and the live-probe request/payload/reproduction for
        anything the DAST bridge confirmed. Same data the Controls page's
        Evidence tab renders — this mirrors it in the PDF instead of
        collapsing everything down to a single "file:line — note" line.
        """
        flows: list = []
        for e in (evidence or [])[:limit]:
            location = f"{e['file']}:{e.get('line') or ''}".rstrip(":") if e.get("file") else None
            metrics = []
            if e.get("cvss_score") is not None:
                metrics.append(f"CVSS {e['cvss_score']}")
            if e.get("severity"):
                metrics.append(f"Severity: {_pdf_text(str(e['severity']).title())}")
            if e.get("confidence") is not None:
                try:
                    metrics.append(f"Confidence: {round(float(e['confidence']) * 100)}%")
                except (TypeError, ValueError):
                    pass
            if e.get("cwe"):
                metrics.append(_pdf_text(str(e["cwe"])))

            head_bits = ([_pdf_text(location)] if location else []) + metrics
            head = " &nbsp;|&nbsp; ".join(head_bits)
            note = _pdf_text(e.get("note") or "")
            text = "<br/>".join(p for p in (f"<b>{head}</b>" if head else "", note) if p) or "No inline evidence recorded."
            flows.append(Paragraph(text, cell_style))

            snippet = e.get("code_snippet")
            if snippet:
                snippet = str(snippet)
                truncated = len(snippet) > 800
                flows.append(Preformatted(snippet[:800] + (" …" if truncated else ""), code_style))

            live = e.get("live_proof")
            coarse = e.get("dynamic_corroboration")
            proof = live or coarse
            if proof:
                label_map = ASVSService._LIVE_PROOF_LABEL if live else ASVSService._COARSE_DYNAMIC_LABEL
                label = label_map.get(proof.get("verdict"), "Tested live — result was inconclusive")
                lp_lines = [f"<b>{_pdf_text(label)}</b>"]
                request = " ".join(filter(None, [proof.get("method"), proof.get("url")]))
                if request:
                    lp_lines.append(_pdf_text(request))
                if proof.get("payload"):
                    lp_lines.append(f"Payload: {_pdf_text(str(proof['payload'])[:300])}")
                if proof.get("note"):
                    lp_lines.append(f"Result: {_pdf_text(str(proof['note'])[:300])}")
                flows.append(Paragraph("<br/>".join(lp_lines), cell_style))
                if proof.get("reproduction"):
                    repro = str(proof["reproduction"])
                    truncated = len(repro) > 600
                    flows.append(Preformatted(repro[:600] + (" …" if truncated else ""), code_style))
        return flows

    async def export_pdf(
        self,
        scan_id: str,
        repo_name: Optional[str] = None,
        branch: Optional[str] = None,
        target_url: Optional[str] = None,
        user: Optional[dict] = None,
    ) -> Optional[bytes]:
        if not REPORTLAB_AVAILABLE:
            logger.error("reportlab not available. Install it with: pip install reportlab")
            return None

        summary = await self.get_compliance_summary(scan_id, user=user)
        controls = await self.list_controls()
        controls_by_id = {c["control_id"]: c for c in controls}
        exec_summary_text = await self._generate_executive_summary(summary)

        failing = [r for r in summary["results"].values() if r["verdict"] == "fail"]
        not_tested_count = sum(1 for r in summary["results"].values() if r["verdict"] == "not_tested")
        overall = summary["levels"].get("overall", summary["levels"].get("L3", {}))

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=letter,
            topMargin=0.65 * inch, bottomMargin=0.65 * inch,
            leftMargin=0.65 * inch, rightMargin=0.65 * inch,
        )
        styles = getSampleStyleSheet()
        brand_style = ParagraphStyle(
            "Brand", parent=styles["Normal"], fontSize=9.5,
            textColor=colors.HexColor("#0369a1"), spaceAfter=8,
            fontName="Helvetica-Bold",
        )
        title_style = ParagraphStyle(
            "ASVSTitle", parent=styles["Heading1"], fontSize=22, leading=26,
            textColor=colors.HexColor("#0f172a"), spaceAfter=8,
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "ASVSSubtitle", parent=styles["Normal"], fontSize=10.5, leading=14,
            textColor=colors.HexColor("#334155"), alignment=TA_CENTER, spaceAfter=10,
        )
        meta_style = ParagraphStyle(
            "ASVSMeta", parent=styles["Normal"], fontSize=8.5, leading=11,
            textColor=colors.HexColor("#475569"),
        )
        meta_label_style = ParagraphStyle(
            "ASVSMetaLabel", parent=meta_style,
            textColor=colors.HexColor("#64748b"), fontName="Helvetica-Bold",
        )
        section_style = ParagraphStyle(
            "ASVSSection", parent=styles["Heading2"], fontSize=14,
            textColor=colors.HexColor("#0f172a"), spaceBefore=18, spaceAfter=7,
            fontName="Helvetica-Bold",
        )
        body_style = ParagraphStyle(
            "ASVSBody", parent=styles["Normal"], fontSize=9.5, leading=14.5,
            alignment=TA_JUSTIFY, spaceAfter=8,
        )
        cell_style = ParagraphStyle("ASVSCell", parent=styles["Normal"], fontSize=8, leading=10.2)
        code_style = ParagraphStyle(
            "ASVSCode", parent=styles["Normal"], fontName="Courier", fontSize=7.5, leading=9.5,
            textColor=colors.HexColor("#0f172a"), leftIndent=8, spaceAfter=4, spaceBefore=2,
        )
        cover_app_style = ParagraphStyle(
            "CoverAppTitle", parent=styles["Heading1"], fontSize=34, leading=40,
            textColor=colors.HexColor("#0f172a"), alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=8,
        )
        cover_report_style = ParagraphStyle(
            "CoverReportTitle", parent=styles["Heading2"], fontSize=18, leading=23,
            textColor=colors.HexColor("#0369a1"), alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceBefore=18, spaceAfter=8,
        )
        cover_desc_style = ParagraphStyle(
            "CoverDescription", parent=styles["Normal"], fontSize=10.5, leading=15,
            textColor=colors.HexColor("#334155"), alignment=TA_CENTER,
            leftIndent=0.35 * inch, rightIndent=0.35 * inch, spaceAfter=12,
        )
        cover_kicker_style = ParagraphStyle(
            "CoverKicker", parent=styles["Normal"], fontSize=8.5, leading=11,
            textColor=colors.HexColor("#64748b"), alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=4,
        )

        # ── Cover / header block ──────────────────────────────────────────────
        target_label = (
            _pdf_text(repo_name)
            or (f"Dynamic scan - {_pdf_text(target_url)}" if target_url else "Direct code scan")
        )
        target_line = f"Target: {target_label}" + (f"  |  Branch: {_pdf_text(branch)}" if branch else "")
        story = [
            Spacer(1, 0.45 * inch),
            _control_gate_logo(82),
            Spacer(1, 0.18 * inch),
            Paragraph("ControlGate", cover_app_style),
            Paragraph("APPLICATION SECURITY AND COMPLIANCE ASSURANCE", cover_kicker_style),
            Paragraph(
                "ControlGate provides automated application security analysis, live verification, "
                "dependency intelligence, and reviewer attestations mapped to OWASP ASVS controls.",
                cover_desc_style,
            ),
            Paragraph("OWASP ASVS 5.0.0 Compliance Report", cover_report_style),
            Paragraph(target_line, subtitle_style),
        ]
        meta_rows = [[
            Paragraph("Scan ID", meta_label_style),
            Paragraph(_pdf_text(scan_id), meta_style),
            Paragraph("Generated", meta_label_style),
            Paragraph(_pdf_text(summary["generated_at"]), meta_style),
        ]]
        meta_table = Table(meta_rows, colWidths=[52, 168, 64, 216])
        meta_table.hAlign = "CENTER"
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dbe4ee")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.extend([meta_table, Spacer(1, 0.2 * inch)])

        # Headline stat row
        headline_rows = [["Overall Completion", "Passing", "Failing", "Not Tested"]]
        headline_rows.append([
            f"{overall.get('pct', 0)}%", str(overall.get("passed", 0)), str(len(failing)), str(not_tested_count),
        ])
        story.append(self._styled_table(headline_rows, col_widths=[150, 110, 110, 120], big=True))
        story.append(Spacer(1, 0.12 * inch))
        story.append(PageBreak())

        # ── Executive summary ─────────────────────────────────────────────────
        story.append(Paragraph("Executive Summary", section_style))
        for para in exec_summary_text.split("\n\n"):
            if para.strip():
                story.append(Paragraph(_pdf_text(para.strip()), body_style))

        # ── Methodology ────────────────────────────────────────────────────────
        story.append(Paragraph("Methodology", section_style))
        for para in self._methodology_paragraphs(len(controls)):
            story.append(Paragraph(para, body_style))

        # ── Level completion ───────────────────────────────────────────────────
        story.append(Paragraph("Compliance Breakdown", section_style))
        level_rows = [["Scope", "Passed", "Total", "%"]]
        scope_order = [
            ("overall", "Overall"),
            ("L1", "Level 1"),
            ("L2", "Level 2"),
            ("L3", "Level 3"),
        ]
        for level, label in scope_order:
            data = summary["levels"].get(level)
            if not data:
                continue
            level_rows.append([label, str(data["passed"]), str(data["total"]), f"{data['pct']}%"])
        story.append(self._styled_table(level_rows))

        # ── Per-chapter breakdown ──────────────────────────────────────────────
        story.append(Paragraph("Per-Chapter Breakdown", section_style))
        chapter_rows = [["Chapter", "Pass", "Fail", "N/A", "Manual Review", "Not Tested", "% Pass"]]
        for ch in summary["chapters"]:
            c = ch["counts"]
            pct = round((c.get("pass", 0) / ch["control_count"]) * 100) if ch["control_count"] else 0
            chapter_rows.append([
                f"{ch['chapter_id']}: {ch['title']}",
                str(c.get("pass", 0)), str(c.get("fail", 0)), str(c.get("n_a", 0)),
                str(c.get("manual_review", 0)), str(c.get("not_tested", 0)), f"{pct}%",
            ])
        story.append(self._styled_table(chapter_rows))

        # ── Failing / manual-review controls detail ─────────────────────────────
        # Shared block renderer — both sections below show the exact same
        # per-control shape (heading, method/confidence meta, full evidence
        # including live_proof, LLM analysis), just with a different heading
        # color/count so a reader can't confuse "definitively failing" with
        # "found something, but nobody's confirmed it's real yet".
        def _control_detail_block(r: dict, heading_hex: str) -> list:
            control = controls_by_id.get(r["control_id"], {})
            strategy_label = _pdf_text(str(control.get("detection_strategy", "")).replace("_", " "))
            confidence = r.get("confidence")
            head_meta = [f"Method: {strategy_label}"] if strategy_label else []
            if confidence is not None:
                try:
                    head_meta.append(f"Confidence: {round(float(confidence) * 100)}%")
                except (TypeError, ValueError):
                    pass
            block = [
                Paragraph(
                    f"<b>{_pdf_text(r['control_id'])}</b> — {_pdf_text(control.get('description', ''))}",
                    ParagraphStyle("FailHead", parent=cell_style, fontSize=9.5, textColor=colors.HexColor(heading_hex), spaceAfter=2),
                ),
            ]
            if head_meta:
                block.append(Paragraph(" &nbsp;|&nbsp; ".join(head_meta), ParagraphStyle(
                    "FailMeta", parent=cell_style, fontSize=7.5, textColor=colors.HexColor("#64748b"), spaceAfter=4,
                )))
            block.append(Paragraph("<b>Evidence:</b>", cell_style))
            # Full evidence per item — CVSS/severity/confidence, code
            # snippet, and live-probe request/payload/reproduction where the
            # detection strategy actually produced them (see
            # _evidence_flowables above and the *_MERGE functions that feed
            # it — including _dynamic_evidence_for_control's coarse
            # dynamic-corroboration items), not just a collapsed
            # "file:line — note" line. limit raised from the 4-item default:
            # a control like V8.2.1 can now carry a static hit PLUS dozens of
            # coarse dynamic checks (some pass, some fail) sharing its
            # control_id — truncating at 4 risked showing only the first few
            # (often all the same verdict) and misrepresenting the mix.
            block.extend(self._evidence_flowables(r.get("evidence") or [], cell_style, code_style, limit=12))
            explanation = r.get("llm_explanation")
            if explanation:
                block.append(Paragraph(f"<b>Analysis:</b> {_pdf_text(explanation)}", cell_style))
            block.append(Spacer(1, 0.14 * inch))
            return block

        if failing:
            story.append(PageBreak())
            story.append(Paragraph(f"Failing Controls ({len(failing)})", section_style))
            for r in sorted(failing, key=lambda r: r["control_id"]):
                story.append(KeepTogether(_control_detail_block(r, "#dc2626")))

        # Controls where a static pattern matched but nothing confirmed it
        # (LLM unavailable/rate-limited, no live bridge reproduction) —
        # previously these got a bare "MANUAL REVIEW" badge in the appendix
        # table below and NO evidence anywhere in the report, even after
        # _dynamic_evidence_for_control started attaching real dynamic
        # corroboration to them. A reader had no way to see WHY a control
        # needed review, or that other routes for the same control passed
        # cleanly — this section is that missing detail, same shape as
        # Failing Controls above, just blue (matches _VERDICT_HEX's
        # manual_review color) instead of red to signal "unconfirmed",
        # not "confirmed broken".
        manual_review = [r for r in summary["results"].values() if r["verdict"] == "manual_review"]
        if manual_review:
            story.append(PageBreak())
            story.append(Paragraph(f"Needs Manual Review ({len(manual_review)})", section_style))
            for r in sorted(manual_review, key=lambda r: r["control_id"]):
                story.append(KeepTogether(_control_detail_block(r, _VERDICT_HEX.get("manual_review", "#2563eb"))))

        # ── Full control register (appendix) ───────────────────────────────────
        story.append(PageBreak())
        story.append(Paragraph("Appendix: Full Control Register", section_style))
        story.append(Paragraph(
            "Every ASVS 5.0.0 requirement in the current catalog and its current verdict, for full traceability.",
            body_style,
        ))
        register_rows = [["Control", "Description", "Level", "Strategy", "Verdict"]]
        for c in controls:
            r = summary["results"].get(c["control_id"], {})
            verdict = r.get("verdict", "not_tested")
            register_rows.append([
                c["control_id"],
                Paragraph(_pdf_text(c.get("description", "")), cell_style),
                c.get("level", ""),
                c.get("detection_strategy", "").replace("_", " "),
                Paragraph(f'<font color="{_VERDICT_HEX.get(verdict, "#000000")}"><b>{verdict.replace("_", " ").upper()}</b></font>', cell_style),
            ])
        story.append(self._styled_table(register_rows, col_widths=[55, 260, 35, 75, 75], repeat_header=True))

        def _footer(canvas_obj, doc_obj):
            canvas_obj.saveState()
            canvas_obj.setFont("Helvetica", 8)
            canvas_obj.setFillColor(colors.HexColor("#94a3b8"))
            canvas_obj.drawString(0.65 * inch, 0.45 * inch, "ControlGate - OWASP ASVS 5.0.0 Compliance Report")
            canvas_obj.drawRightString(letter[0] - 0.65 * inch, 0.45 * inch, f"Page {doc_obj.page}")
            canvas_obj.restoreState()

        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        return buffer.getvalue()

    @staticmethod
    def _styled_table(rows: list[list], col_widths: Optional[list[int]] = None, big: bool = False, repeat_header: bool = False) -> "Table":
        table = Table(rows, colWidths=col_widths, repeatRows=1 if repeat_header else 0)
        table.hAlign = "CENTER"
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10 if big else 8),
            ("LINEBELOW", (0, 0), (-1, 0), 0.75, colors.HexColor("#0369a1")),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 8 if big else 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8 if big else 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8 if big else 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8 if big else 5),
        ]
        if big:
            style.append(("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"))
            style.append(("FONTSIZE", (0, 1), (-1, 1), 16))
            style.append(("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#0369a1")))
            style.append(("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafc")))
        table.setStyle(TableStyle(style))
        return table
