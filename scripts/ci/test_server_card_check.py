import copy
import json

import server_card_check as check


def current_card():
    return check.load_card()


def test_current_server_card_is_valid():
    assert check.validate_card(current_card()) == []


def test_server_card_rejects_tool_drift():
    card = current_card()
    card["tools"] = [tool for tool in card["tools"] if tool["name"] != "prove_template"]

    failures = check.validate_card(card)

    assert any("tools must match current public MCP tool set" in failure for failure in failures)


def test_server_card_rejects_gated_template_markers():
    card = copy.deepcopy(current_card())
    card["metadata"]["description"] += " range_proof"

    failures = check.validate_card(json.loads(json.dumps(card)))

    assert any("gated/non-live templates" in failure for failure in failures)
