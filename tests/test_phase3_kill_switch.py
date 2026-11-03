from __future__ import annotations

import json

import pytest

from phase3.kill_switch import KillSwitchError, disable_live_features


TOPIC = "arn:aws:sns:us-east-1:123456789012:phase3-budget-kill"


def _event(*, topic=TOPIC, message="budget threshold crossed"):
    return {
        "Records": [
            {
                "EventSource": "aws:sns",
                "Sns": {"Type": "Notification", "TopicArn": topic, "Message": message},
            }
        ]
    }


class Table:
    def __init__(self):
        self.updates = []

    def update_item(self, **kwargs):
        self.updates.append(kwargs)


def test_budget_kill_switch_atomically_disables_rin_and_selects_static_mode():
    table = Table()

    result = disable_live_features(_event(), table=table, expected_topic_arn=TOPIC)

    assert result == {"status": "DISABLED"}
    assert len(table.updates) == 1
    update = table.updates[0]
    assert update["Key"] == {"pk": "PLATFORM", "sk": "CONFIG"}
    assert update["ConditionExpression"] == "attribute_exists(pk) AND attribute_exists(sk)"
    assert "rin_enabled = :disabled" in update["UpdateExpression"]
    assert "static_mode = :enabled" in update["UpdateExpression"]
    assert update["ExpressionAttributeValues"] == {":disabled": False, ":enabled": True}


@pytest.mark.parametrize(
    "event",
    [
        {},
        {"Records": []},
        _event(topic="arn:aws:sns:us-east-1:999999999999:other"),
        {"Records": [{"EventSource": "aws:sqs", "Sns": {}}]},
        _event(message="x" * 262_145),
        {"Records": [{"EventSource": "aws:sns", "Sns": {"Type": "SubscriptionConfirmation", "TopicArn": TOPIC, "Message": "x"}}]},
    ],
)
def test_kill_switch_rejects_untrusted_or_oversized_events_without_writes(event):
    table = Table()

    with pytest.raises(KillSwitchError):
        disable_live_features(event, table=table, expected_topic_arn=TOPIC)

    assert table.updates == []


def test_kill_switch_error_does_not_echo_budget_message():
    class FailingTable:
        def update_item(self, **_kwargs):
            raise RuntimeError("private-backend-error")

    with pytest.raises(KillSwitchError) as exc:
        disable_live_features(_event(message=json.dumps({"secret": "do-not-echo"})), table=FailingTable(), expected_topic_arn=TOPIC)

    assert "do-not-echo" not in str(exc.value)
    assert "private-backend-error" not in str(exc.value)
