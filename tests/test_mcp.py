from __future__ import annotations

from typing import Any

import pytest

from turnstile.mcp import (
    CLIENT_CAPABILITIES_KEY,
    PROTOCOL_VERSION_KEY,
    MalformedRequest,
    filter_tool_list,
    is_complete,
    parse_tool_call,
)


def message(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "get_weather",
            "arguments": {"location": "New York"},
            "_meta": {PROTOCOL_VERSION_KEY: "2026-07-28", CLIENT_CAPABILITIES_KEY: {}},
        },
    }
    base.update(overrides)
    return base


class TestParsing:
    def test_parses_the_specs_own_example(self) -> None:
        assert parse_tool_call(message()) == ("get_weather", {"location": "New York"})

    def test_arguments_default_to_empty(self) -> None:
        msg = message()
        del msg["params"]["arguments"]
        assert parse_tool_call(msg) == ("get_weather", {})

    @pytest.mark.parametrize("jsonrpc", ["1.0", None, 2.0])
    def test_wrong_jsonrpc_version_is_rejected(self, jsonrpc: Any) -> None:
        with pytest.raises(MalformedRequest):
            parse_tool_call(message(jsonrpc=jsonrpc))

    def test_wrong_method_is_rejected(self) -> None:
        with pytest.raises(MalformedRequest, match="tools/call"):
            parse_tool_call(message(method="resources/read"))

    def test_empty_tool_name_is_rejected(self) -> None:
        msg = message()
        msg["params"]["name"] = ""
        with pytest.raises(MalformedRequest, match="non-empty"):
            parse_tool_call(msg)

    def test_non_object_arguments_are_rejected(self) -> None:
        msg = message()
        msg["params"]["arguments"] = ["not", "an", "object"]
        with pytest.raises(MalformedRequest, match="object"):
            parse_tool_call(msg)


class TestRequiredMeta:
    """2026-07-28 makes these per-request fields mandatory precisely so a
    stateless intermediary can read them without a handshake."""

    def test_absent_meta_is_rejected(self) -> None:
        msg = message()
        del msg["params"]["_meta"]
        with pytest.raises(MalformedRequest, match="_meta is required"):
            parse_tool_call(msg)

    @pytest.mark.parametrize("key", [PROTOCOL_VERSION_KEY, CLIENT_CAPABILITIES_KEY])
    def test_each_required_field_is_checked(self, key: str) -> None:
        msg = message()
        del msg["params"]["_meta"][key]
        with pytest.raises(MalformedRequest, match=key):
            parse_tool_call(msg)

    def test_protocol_version_must_be_a_string(self) -> None:
        msg = message()
        msg["params"]["_meta"][PROTOCOL_VERSION_KEY] = 20260728
        with pytest.raises(MalformedRequest, match="must be a string"):
            parse_tool_call(msg)

    def test_error_code_is_invalid_params(self) -> None:
        msg = message()
        del msg["params"]["_meta"]
        with pytest.raises(MalformedRequest) as excinfo:
            parse_tool_call(msg)
        assert excinfo.value.code == -32602


class TestResultType:
    def test_complete_is_complete(self) -> None:
        assert is_complete({"resultType": "complete", "content": []})

    def test_absent_result_type_is_treated_as_complete(self) -> None:
        # Backwards compatibility: servers on earlier revisions omit it, and
        # defaulting the other way would make them all look like they were
        # asking for more input.
        assert is_complete({"content": []})

    def test_input_required_is_not_complete(self) -> None:
        assert not is_complete({"resultType": "input_required", "inputRequests": {}})


class TestToolListFiltering:
    def test_drops_tools_not_in_the_allowed_set(self) -> None:
        result = {
            "resultType": "complete",
            "tools": [{"name": "read_file"}, {"name": "delete_everything"}],
        }
        filtered = filter_tool_list(result, {"read_file"})
        assert [tool["name"] for tool in filtered["tools"]] == ["read_file"]

    def test_preserves_other_result_fields(self) -> None:
        result = {"resultType": "complete", "tools": [], "nextCursor": "abc", "ttlMs": 300000}
        filtered = filter_tool_list(result, set())
        assert filtered["nextCursor"] == "abc"
        assert filtered["ttlMs"] == 300000

    def test_result_without_tools_is_returned_unchanged(self) -> None:
        result = {"resultType": "complete"}
        assert filter_tool_list(result, {"anything"}) == result

    def test_does_not_mutate_the_input(self) -> None:
        result: dict[str, Any] = {"tools": [{"name": "a"}, {"name": "b"}]}
        filter_tool_list(result, {"a"})
        assert len(result["tools"]) == 2
