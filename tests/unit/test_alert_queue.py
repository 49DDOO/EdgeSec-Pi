from __future__ import annotations

import asyncio

import pytest

import alert_queue


@pytest.mark.unit
def test_alert_priority_queue_processes_attack_before_sca() -> None:
    async def scenario() -> None:
        queue = alert_queue.AlertPriorityQueue()
        sca = {
            "rule": {
                "id": "19007",
                "level": 7,
                "description": "CIS benchmark failed",
                "groups": ["sca"],
            },
            "full_log": "SCA check failed",
        }
        brute_force = {
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "sshd: brute force trying to get access",
                "groups": ["syslog", "sshd", "authentication_failures"],
            },
            "full_log": "Failed password for invalid user admin from 203.0.113.45",
        }

        queue.put_nowait(sca)
        queue.put_nowait(brute_force)

        assert await queue.get() is brute_force
        queue.task_done()
        assert await queue.get() is sca
        queue.task_done()

    asyncio.run(scenario())


@pytest.mark.unit
def test_alert_priority_queue_keeps_fifo_with_same_priority() -> None:
    async def scenario() -> None:
        queue = alert_queue.AlertPriorityQueue()
        first = {"rule": {"id": "100", "level": 7, "description": "service changed"}}
        second = {"rule": {"id": "101", "level": 7, "description": "service changed"}}

        queue.put_nowait(first)
        queue.put_nowait(second)

        assert await queue.get() is first
        queue.task_done()
        assert await queue.get() is second
        queue.task_done()

    asyncio.run(scenario())
