"""Track C3 — OpenAPI/Swagger spec-driven target discovery.

parse_openapi_spec is pure (dict in, list out) so most of this file tests it
directly with no session/transport needed. fetch_openapi_spec is exercised
against httpx.MockTransport, same pattern as test_dast_crawler.py.
"""
import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig
from app.domain.analysis.dast.openapi_discovery import (
    DiscoveredEndpoint,
    fetch_openapi_spec,
    parse_openapi_spec,
    parse_spec_text,
)
from app.domain.analysis.dast.session import DastSession

BASE = "https://target.example"


def _session(handler) -> DastSession:
    return DastSession(ActorConfig(), resolve=False, transport=httpx.MockTransport(handler))


class TestPathParamSubstitution:
    def test_required_path_param_with_example_uses_example(self):
        spec = {
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer", "example": 42}},
                        ],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints == [DiscoveredEndpoint(method="GET", url=f"{BASE}/users/42")]

    def test_required_path_param_without_example_uses_placeholder(self):
        spec = {
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [{"name": "id", "in": "path", "required": True}],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints == [DiscoveredEndpoint(method="GET", url=f"{BASE}/users/1")]

    def test_swagger2_style_default_on_parameter_directly(self):
        spec = {
            "paths": {
                "/orders/{orderId}": {
                    "get": {
                        "parameters": [{"name": "orderId", "in": "path", "required": True, "default": "999"}],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints[0].url == f"{BASE}/orders/999"

    def test_enum_prefers_first_value(self):
        spec = {
            "paths": {
                "/status/{state}": {
                    "get": {
                        "parameters": [
                            {"name": "state", "in": "path", "required": True, "schema": {"enum": ["open", "closed"]}},
                        ],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints[0].url == f"{BASE}/status/open"

    def test_path_level_shared_parameters_apply_to_operation(self):
        spec = {
            "paths": {
                "/items/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": True, "example": "abc"}],
                    "get": {},
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints[0].url == f"{BASE}/items/abc"

    def test_unresolvable_array_type_path_param_is_skipped(self):
        spec = {
            "paths": {
                "/batch/{ids}": {
                    "get": {
                        "parameters": [{"name": "ids", "in": "path", "required": True, "schema": {"type": "array"}}],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints == []

    def test_unresolvable_object_type_path_param_is_skipped(self):
        spec = {
            "paths": {
                "/filter/{criteria}": {
                    "get": {
                        "parameters": [{"name": "criteria", "in": "path", "required": True, "schema": {"type": "object"}}],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints == []

    def test_multiple_path_params_all_resolved(self):
        spec = {
            "paths": {
                "/orgs/{orgId}/users/{userId}": {
                    "get": {
                        "parameters": [
                            {"name": "orgId", "in": "path", "required": True, "example": "acme"},
                            {"name": "userId", "in": "path", "required": True, "example": "7"},
                        ],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints[0].url == f"{BASE}/orgs/acme/users/7"


class TestQueryParamHandling:
    def test_query_param_with_example_appended(self):
        spec = {
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [{"name": "q", "in": "query", "schema": {"example": "widget"}}],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints[0].url == f"{BASE}/search?q=widget"

    def test_query_param_without_example_uses_placeholder(self):
        spec = {
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [{"name": "q", "in": "query"}],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints[0].url == f"{BASE}/search?q=1"

    def test_multiple_query_params_all_appended(self):
        spec = {
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [
                            {"name": "q", "in": "query", "example": "widget"},
                            {"name": "page", "in": "query", "example": "2"},
                        ],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert "q=widget" in endpoints[0].url
        assert "page=2" in endpoints[0].url

    def test_no_query_params_yields_bare_url(self):
        spec = {"paths": {"/health": {"get": {}}}}
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints[0].url == f"{BASE}/health"

    def test_body_only_operation_is_still_discovered_as_bare_url(self):
        # Request bodies are explicitly out of scope for this pass (see
        # module docstring) — the URL is still discovered, just without any
        # body-derived query params, since nothing downstream tests bodies yet.
        spec = {
            "paths": {
                "/users": {
                    "post": {
                        "requestBody": {
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        },
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints == [DiscoveredEndpoint(method="POST", url=f"{BASE}/users")]


class TestMethodCoverage:
    def test_multiple_methods_on_same_path_each_discovered(self):
        spec = {
            "paths": {
                "/items/{id}": {
                    "get": {"parameters": [{"name": "id", "in": "path", "example": "1"}]},
                    "delete": {"parameters": [{"name": "id", "in": "path", "example": "1"}]},
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        methods = {e.method for e in endpoints}
        assert methods == {"GET", "DELETE"}

    def test_non_http_method_keys_are_ignored(self):
        # e.g. a path-item-level 'summary'/'description' field, or a vendor
        # extension key like 'x-internal' — neither is an HTTP method.
        spec = {
            "paths": {
                "/items": {
                    "summary": "Item collection",
                    "get": {},
                },
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert len(endpoints) == 1
        assert endpoints[0].method == "GET"


class TestMalformedAndEmptySpecs:
    def test_empty_spec_returns_empty_list(self):
        assert parse_openapi_spec({}, BASE) == []

    def test_missing_paths_key_returns_empty_list(self):
        assert parse_openapi_spec({"openapi": "3.0.0"}, BASE) == []

    def test_paths_not_a_dict_returns_empty_list(self):
        assert parse_openapi_spec({"paths": ["not", "a", "dict"]}, BASE) == []

    def test_non_dict_spec_returns_empty_list(self):
        assert parse_openapi_spec(None, BASE) == []  # type: ignore[arg-type]
        assert parse_openapi_spec("garbage", BASE) == []  # type: ignore[arg-type]

    def test_operation_that_is_not_a_dict_is_skipped(self):
        spec = {"paths": {"/broken": {"get": "not-an-operation"}}}
        assert parse_openapi_spec(spec, BASE) == []

    def test_one_malformed_operation_does_not_block_the_rest(self):
        spec = {
            "paths": {
                "/broken": {"get": "not-an-operation"},
                "/ok": {"get": {}},
            },
        }
        endpoints = parse_openapi_spec(spec, BASE)
        assert endpoints == [DiscoveredEndpoint(method="GET", url=f"{BASE}/ok")]


class TestSpecTextParsing:
    def test_json_text_parses(self):
        spec = parse_spec_text('{"paths": {"/health": {"get": {}}}}')
        assert spec == {"paths": {"/health": {"get": {}}}}

    def test_yaml_text_parses(self):
        spec = parse_spec_text(
            "paths:\n"
            "  /health:\n"
            "    get: {}\n"
        )
        assert spec == {"paths": {"/health": {"get": {}}}}

    def test_yaml_that_is_also_valid_json_prefers_json_path(self):
        # Sanity check only — both parsers must agree on a spec this simple;
        # the point is neither path raises.
        spec = parse_spec_text('{"paths": {}}')
        assert spec == {"paths": {}}

    def test_garbage_text_raises_value_error(self):
        with pytest.raises(ValueError):
            parse_spec_text("not: valid: yaml: at: all: {[")

    def test_scalar_yaml_document_raises_value_error(self):
        # Parses fine as YAML but yields a plain string, not an object/dict.
        with pytest.raises(ValueError):
            parse_spec_text("just a plain string")


class TestFetchOpenapiSpec:
    async def test_fetches_and_parses_json_body(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"paths": {"/health": {"get": {}}}})

        async with _session(handler) as session:
            spec = await fetch_openapi_spec(session, f"{BASE}/openapi.json")

        assert spec == {"paths": {"/health": {"get": {}}}}

    async def test_fetches_and_parses_yaml_body(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="paths:\n  /health:\n    get: {}\n")

        async with _session(handler) as session:
            spec = await fetch_openapi_spec(session, f"{BASE}/openapi.yaml")

        assert spec == {"paths": {"/health": {"get": {}}}}

    async def test_http_error_status_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="not found")

        async with _session(handler) as session:
            with pytest.raises(httpx.HTTPStatusError):
                await fetch_openapi_spec(session, f"{BASE}/openapi.json")
