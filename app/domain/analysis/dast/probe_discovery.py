"""Auto-discovery of IDOR (V8.2.1) / mass-assignment (V15.3.3) probe
candidates for the GUI's "Discover probe targets" step.

The GUI previously required the user to hand-type a real owned-resource URL
for every probe (an order ID, a product ID, ...) — the same values a black-
box tester would otherwise dig out with curl before ever touching the scan
form. Most REST APIs expose those values for free: an authenticated "list my
resources" endpoint (GET /orders, GET /products, ...) that returns a JSON
array of objects, each carrying an id. This module does a small authenticated
GET sweep across the configured targets, walks each JSON response looking
for that shape, and turns every hit into:
  - an IDOR candidate: GET the resource's own detail URL (list_url/{id})
  - a mass-assignment candidate, when the object also carries an
    ownership-looking field (seller_id, owner_id, user_id, role, ...) —
    attempting to overwrite that field is the actual V15.3.3 test.

Best-effort and intentionally narrow, same spirit as bridge.py: a target
that isn't JSON, or returns nothing shaped like a resource list, just
contributes no candidates — never a guess presented as a real one. This
makes GET-only requests (same discipline as crawler.py) and never runs a
probe itself; everything it returns is for the caller (the GUI) to review,
edit, or delete before any scan actually executes it.

Race probes (V2.3.4) are deliberately NOT auto-discovered here — a valid
request body can't be inferred generically without an OpenAPI schema or a
captured form submission, and a guessed body would just make the probe
worthless (every concurrent request 400s, "no race" isn't a real result).
"""
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from app.domain.analysis.dast.session import DastSession

logger = logging.getLogger(__name__)

MAX_CANDIDATES_PER_KIND = 10

_ID_KEYS = ("id", "_id", "uuid", "ID")
_OWNER_KEYS = {
    "seller_id", "sellerid", "owner_id", "ownerid", "user_id", "userid",
    "created_by", "createdby", "author_id", "authorid",
}
# Common "who is currently logged in" endpoints — tried relative to each
# target's origin root to resolve the second actor's own id (makes the
# mass-assignment ownership-hijack candidate use a real id instead of a
# placeholder). Best-effort: whichever one 200s with an id-shaped JSON body
# wins; none matching just leaves the placeholder for the user to fill in.
_WHOAMI_PATHS = ("me", "auth/me", "profile", "users/me")


@dataclass
class IdorCandidate:
    scenario_id: str
    owner_resource_url: str
    method: str = "GET"
    source_url: str = ""


@dataclass
class MassAssignmentCandidate:
    scenario_id: str
    update_url: str
    update_method: str = "PUT"
    injected_field: str = "role"
    injected_value: Any = "admin"
    source_url: str = ""


@dataclass
class ProbeDiscoveryResult:
    idor_candidates: List[IdorCandidate] = field(default_factory=list)
    mass_assignment_candidates: List[MassAssignmentCandidate] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def _looks_like_resource(item: dict) -> bool:
    return any(k in item for k in _ID_KEYS)


def _extract_id(item: dict) -> Optional[str]:
    for k in _ID_KEYS:
        value = item.get(k)
        if isinstance(value, (str, int)) and str(value):
            return str(value)
    return None


def _walk_json_for_resource_lists(node: Any, list_url: str) -> Iterator[Tuple[dict, str]]:
    """Depth-first search through a parsed JSON body for every list of
    plausible resource dicts — covers both a bare array response and the
    common enveloped shape ({"success": true, "data": {"orders": [...]}})."""
    if isinstance(node, list):
        if node and all(isinstance(i, dict) for i in node):
            for item in node:
                if _looks_like_resource(item):
                    yield item, list_url
        for item in node:
            yield from _walk_json_for_resource_lists(item, list_url)
    elif isinstance(node, dict):
        for value in node.values():
            yield from _walk_json_for_resource_lists(value, list_url)


def _find_first_id_bearing_object(node: Any) -> Optional[dict]:
    """Same depth-first search as _walk_json_for_resource_lists, but for a
    single id-bearing object rather than an array of them — a "who am I"
    endpoint's id is almost never inside a list (this app's shape:
    {"success": true, "data": {"user": {"id": "...", ...}}}), so the list-
    only walker above never finds it. Pre-order (outermost match wins),
    which is the right bias for a whoami-shaped response: the current
    user's own object is normally the first/only id-bearing thing in it."""
    if isinstance(node, dict):
        if _looks_like_resource(node):
            return node
        for value in node.values():
            found = _find_first_id_bearing_object(value)
            if found:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_first_id_bearing_object(item)
            if found:
                return found
    return None


def _guess_mass_assignment_field(item: dict) -> Optional[Tuple[str, Any]]:
    """Prefer an ownership field (a hijack attempt is the sharper V15.3.3
    test) over the generic role/admin guess when both are present."""
    for key in item.keys():
        if key.lower().replace("-", "").replace("_", "") in {
            k.replace("_", "") for k in _OWNER_KEYS
        }:
            return key, None  # value resolved by the caller (second actor id) or left for the user
    if "role" in item:
        return "role", "admin"
    return None


async def _is_publicly_readable(session: DastSession, url: str) -> bool:
    """A resource anyone — even a fully anonymous, unauthenticated caller —
    can already read isn't a meaningful IDOR test target: there's no
    ownership boundary being violated if reading it never required being a
    specific authenticated user in the first place. Confirmed false
    positive against a real scan: GET /products/:id is intentionally
    public in the marketplace app (no auth middleware on that route at
    all), so a second actor's 200 wasn't evidence of a missing ownership
    check, just the catalog working exactly as designed. Reuses
    DastSession.request_unauthenticated — the same mechanism checks.py's
    UNAUTHENTICATED_ACCESS_ALLOWED already relies on for this exact
    authenticated-vs-anonymous comparison. Errs toward keeping the
    candidate (returns False) if the anonymous probe itself fails — an
    unprovable "maybe public" shouldn't cost a real test."""
    try:
        resp = await session.request_unauthenticated("GET", url)
    except Exception:
        return False
    return 200 <= resp.status_code < 300


async def _resolve_second_actor_id(session: DastSession, target_urls: List[str]) -> Optional[str]:
    # "who am I" lives at the origin root (e.g. /me), not nested under
    # whatever resource path a given target happens to be (a target_url of
    # ".../products" + "/me" would wrongly request ".../products/me") — so
    # this reconstructs just scheme://netloc from each target before trying
    # the candidate suffixes, and dedupes so multiple targets on the same
    # origin (the common case — every service scan reuses the same
    # auth-service origin for login) aren't tried twice.
    origins: List[str] = []
    seen_origins: Set[str] = set()
    for base_url in target_urls:
        parts = urlsplit(base_url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in seen_origins:
            seen_origins.add(origin)
            origins.append(origin)

    for origin in origins[:2]:  # bounded — this is a nice-to-have, not worth a wide sweep
        for suffix in _WHOAMI_PATHS:
            url = origin + "/" + suffix
            try:
                resp = await session.request("GET", url)
            except Exception:
                continue
            if resp.status_code >= 400:
                continue
            content_type = resp.headers.get("content-type", "")
            if "json" not in content_type:
                continue
            try:
                body = resp.json()
            except ValueError:
                continue
            match = _find_first_id_bearing_object(body)
            if match:
                found_id = _extract_id(match)
                if found_id:
                    return found_id
    return None


async def discover_probe_candidates(
    session: DastSession,
    target_urls: List[str],
    *,
    second_actor_session: Optional[DastSession] = None,
) -> ProbeDiscoveryResult:
    result = ProbeDiscoveryResult()
    seen_ids: Set[str] = set()
    # Per-origin cap alongside the overall one — without it, a single
    # resource-heavy origin (e.g. product-service's whole catalog) fills
    # MAX_CANDIDATES_PER_KIND before a sibling origin's own GET endpoints
    # (e.g. order-service's /orders) ever get walked, silently starving
    # every other microservice out of the results for a multi-target sweep.
    per_origin_idor_counts: Dict[str, int] = {}
    per_origin_mass_assignment_counts: Dict[str, int] = {}
    MAX_CANDIDATES_PER_ORIGIN = 2

    second_actor_id: Optional[str] = None
    if second_actor_session is not None:
        try:
            second_actor_id = await _resolve_second_actor_id(second_actor_session, target_urls)
        except Exception as exc:
            logger.debug(f"Second-actor id resolution failed: {exc}")

    for base_url in target_urls:
        try:
            resp = await session.request("GET", base_url)
        except Exception as exc:
            result.notes.append(f"Could not fetch {base_url}: {exc}")
            continue
        content_type = resp.headers.get("content-type", "")
        if "json" not in content_type:
            continue
        try:
            body = resp.json()
        except ValueError:
            continue

        origin_key = f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}"
        for item, list_url in _walk_json_for_resource_lists(body, base_url):
            if (
                len(result.idor_candidates) >= MAX_CANDIDATES_PER_KIND
                and len(result.mass_assignment_candidates) >= MAX_CANDIDATES_PER_KIND
            ):
                break
            if (
                per_origin_idor_counts.get(origin_key, 0) >= MAX_CANDIDATES_PER_ORIGIN
                and per_origin_mass_assignment_counts.get(origin_key, 0) >= MAX_CANDIDATES_PER_ORIGIN
            ):
                continue
            item_id = _extract_id(item)
            if not item_id or item_id in seen_ids:
                continue
            seen_ids.add(item_id)
            detail_url = base_url.rstrip("/") + "/" + item_id

            if (
                len(result.idor_candidates) < MAX_CANDIDATES_PER_KIND
                and per_origin_idor_counts.get(origin_key, 0) < MAX_CANDIDATES_PER_ORIGIN
                and not await _is_publicly_readable(session, detail_url)
            ):
                per_origin_idor_counts[origin_key] = per_origin_idor_counts.get(origin_key, 0) + 1
                result.idor_candidates.append(IdorCandidate(
                    scenario_id=f"idor-auto-{len(result.idor_candidates) + 1}",
                    owner_resource_url=detail_url,
                    source_url=list_url,
                ))

            guess = _guess_mass_assignment_field(item)
            if (
                guess
                and len(result.mass_assignment_candidates) < MAX_CANDIDATES_PER_KIND
                and per_origin_mass_assignment_counts.get(origin_key, 0) < MAX_CANDIDATES_PER_ORIGIN
            ):
                per_origin_mass_assignment_counts[origin_key] = per_origin_mass_assignment_counts.get(origin_key, 0) + 1
                field_name, value = guess
                if value is None:
                    value = second_actor_id or "REPLACE_WITH_ANOTHER_USER_ID"
                result.mass_assignment_candidates.append(MassAssignmentCandidate(
                    scenario_id=f"mass-assign-auto-{len(result.mass_assignment_candidates) + 1}",
                    update_url=detail_url,
                    injected_field=field_name,
                    injected_value=value,
                    source_url=list_url,
                ))

    if not result.idor_candidates and not result.mass_assignment_candidates:
        result.notes.append(
            "No JSON resource-list endpoints found among the given targets — "
            "add IDOR/mass-assignment probes manually below."
        )
    return result
