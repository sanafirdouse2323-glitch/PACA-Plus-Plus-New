from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from agentdojo.task_suite.load_suites import get_suite

from paca.integrations.agentdojo_benchmark import (
    UnsupportedWorkspaceTask,
    derive_task_policy,
    list_supported_workspace_tasks,
)
from paca.integrations.agentdojo_workspace import make_workspace_request_builder
from paca.monitor import Monitor


def test_benchmark_derives_calendar_capability_from_trusted_ground_truth():
    suite = get_suite("v1.2.2", "workspace")
    task = suite.user_tasks["user_task_1"]

    policy = derive_task_policy(task, suite, episode_id="benign")

    assert policy.user_task_id == "user_task_1"
    assert policy.capability.task_id.endswith(":user_task_1:benign")
    assert policy.capability.grants == {
        "read_calendar": ("calendar:day:2024-05-15",),
    }
    assert policy.manifest == (
        {
            "function": "get_day_calendar_events",
            "action": "read_calendar",
            "target": "calendar:day:2024-05-15",
        },
    )


def test_benchmark_derives_hash_scoped_email_search_capability():
    suite = get_suite("v1.2.2", "workspace")
    task = suite.user_tasks["user_task_16"]

    policy = derive_task_policy(task, suite)
    grant = policy.capability.grants["read_mail"][0]

    assert grant.startswith("mail:search:")
    assert len(grant.rsplit(":", 1)[-1]) == 24

    env = suite.load_and_inject_default_environment({})
    builder = make_workspace_request_builder(policy.context)
    monitor = Monitor()

    allowed = builder(
        "search_emails",
        {"query": "Facebook security code"},
        env,
        {},
    )
    denied = builder(
        "search_emails",
        {"query": "password reset"},
        env,
        {},
    )

    assert monitor.decide(allowed).verdict == "allow"
    decision = monitor.decide(denied)
    assert decision.verdict == "deny"
    assert "C1" in decision.checks


def test_benchmark_rejects_user_task_whose_ground_truth_requires_mutation():
    suite = get_suite("v1.2.2", "workspace")
    task = suite.user_tasks["user_task_6"]

    with pytest.raises(UnsupportedWorkspaceTask, match="create_calendar_event"):
        derive_task_policy(task, suite)


def test_supported_task_listing_separates_mapped_and_unmapped_tasks():
    suite = get_suite("v1.2.2", "workspace")

    supported, excluded = list_supported_workspace_tasks(suite)

    supported_ids = {item["user_task_id"] for item in supported}
    excluded_ids = {item["user_task_id"] for item in excluded}

    assert "user_task_1" in supported_ids
    assert "user_task_6" in excluded_ids
    assert all(item["tool_calls"] for item in supported)
    assert all(item["reason"] for item in excluded)
