from datetime import datetime, timedelta, timezone

import pytest

import digest


@pytest.mark.unit
def test_cve_feed_status_falls_back_to_vulnerability_metadata(monkeypatch):
    fresh_epoch = (datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()
    calls: list[list[str]] = []

    def fake_docker_exec(args, timeout=5.0):
        calls.append(args)
        command = " ".join(args)
        if "Feed update process completed" in command:
            return None
        if "updater_vulnerability_feed_manager_metadata" in command:
            return f"{fresh_epoch} /var/ossec/queue/vd_updater/rocksdb/updater_vulnerability_feed_manager_metadata/000001.sst"
        return None

    monkeypatch.setattr(digest, "_docker_exec", fake_docker_exec)

    status = digest._get_cve_feed_status_sync()

    assert status["status"] == "fresh"
    assert status["source"] == "vd_metadata"
    assert status["minutes_ago"] < 180
    assert len(calls) == 2


@pytest.mark.unit
def test_cve_feed_status_prefers_explicit_ossec_log(monkeypatch):
    explicit_ts = datetime.now(timezone.utc) - timedelta(minutes=20)
    line = explicit_ts.strftime("%Y/%m/%d %H:%M:%S") + " wazuh-modulesd:vulnerability-scanner: INFO: Feed update process completed."

    def fake_docker_exec(args, timeout=5.0):
        return line

    monkeypatch.setattr(digest, "_docker_exec", fake_docker_exec)

    status = digest._get_cve_feed_status_sync()

    assert status["status"] == "fresh"
    assert status["source"] == "ossec_log"


@pytest.mark.unit
def test_daily_digest_scheduler_lock_is_exclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(digest, "DIGEST_LOCK_PATH", tmp_path / "digest.lock")

    first = digest._acquire_scheduler_lock()
    try:
        second = digest._acquire_scheduler_lock()
        assert first is not None
        assert second is None
    finally:
        if first is not None:
            digest.fcntl.flock(first.fileno(), digest.fcntl.LOCK_UN)
            first.close()
