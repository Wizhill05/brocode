import json
import os
import socket
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from brocode import maintenance
from brocode.contracts import Policy, Status, TaskRequest
from brocode.maintenance import recover, repair_profile_lock, retention
from brocode.runtime import ProfileLease
from brocode.store import Store


def test_retention_preserves_write_evidence_and_results(tmp_path):
    store = Store(tmp_path / "var")
    runtime = SimpleNamespace(store=store, settings=SimpleNamespace(state_dir=tmp_path / "var"))
    paths = []
    for interactive in (False, True):
        request = TaskRequest(goal="read", policy=Policy(mode="confirm" if interactive else "observe"),
                              operation_key="write" if interactive else None)
        result, _ = store.create_task(request)
        result.status = Status.PARTIAL
        result.updated_at = (datetime.now(UTC) - timedelta(days=60)).isoformat()
        store.update(result)
        # Simulate an old durable record without Store.update refreshing its timestamp.
        result.updated_at = (datetime.now(UTC) - timedelta(days=60)).isoformat()
        with store._connect(write=True) as db:
            db.execute("UPDATE tasks SET result=? WHERE run_id=?", (result.model_dump_json(), result.run_id))
        run = tmp_path / "var/runs" / result.run_id
        run.mkdir(parents=True)
        (run / "result.json").write_text("retained")
        (run / "final.png").write_bytes(b"private media")
        paths.append(run)
    assert len(retention(runtime)["files"]) == 1
    assert (paths[0] / "final.png").exists()
    assert retention(runtime, apply=True)["applied"]
    assert not (paths[0] / "final.png").exists()
    assert (paths[0] / "result.json").exists()
    assert (paths[1] / "final.png").exists()


def test_recover_dead_owner_without_replay(tmp_path, monkeypatch):
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([]))
    store = Store(tmp_path / "var")
    runtime = SimpleNamespace(store=store, settings=SimpleNamespace(state_dir=tmp_path / "var",
                                                                   profile_dir=tmp_path / "profile"))
    result, _ = store.create_task(TaskRequest(goal="read"))
    result.status = Status.RUNNING
    store.update(result)
    run = tmp_path / "var/runs" / result.run_id
    run.mkdir(parents=True)
    (run / "owner.json").write_text(json.dumps({"pid": 2147483647, "created": 0}))
    assert recover(runtime)["recovered"] == [result.run_id]
    assert store.get(result.run_id).error_code == "OWNER_INTERRUPTED"


@pytest.fixture
def stale_profile(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "SingletonLock").symlink_to(f"{socket.gethostname()}-2147483647")
    (profile / "SingletonCookie").symlink_to("123456789")
    (profile / "SingletonSocket").symlink_to(str(tmp_path / "external/socket"))
    # These are never repair candidates, including real Chrome cookie/state files.
    (profile / "Default").mkdir()
    (profile / "Default/Cookies").write_bytes(b"private cookies")
    (profile / "Local State").write_bytes(b"private state")
    (profile / "OtherLink").symlink_to("unrelated")
    monkeypatch.setattr(psutil, "pid_exists", lambda pid: False)
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([]))
    return SimpleNamespace(settings=SimpleNamespace(profile_dir=profile, state_dir=tmp_path / "state"))


def assert_singletons_present(runtime):
    assert all((runtime.settings.profile_dir / name).is_symlink() for name in maintenance._SINGLETONS)


def test_repair_preview_does_not_remove_or_audit(stale_profile):
    report = repair_profile_lock(stale_profile)
    assert report["ok"] and report["repairable"] and not report["applied"]
    assert_singletons_present(stale_profile)
    assert not stale_profile.settings.state_dir.exists()


def test_repair_applies_only_singletons_with_private_audit(stale_profile):
    report = repair_profile_lock(stale_profile, apply=True)
    assert report["ok"] and report["applied"]
    profile = stale_profile.settings.profile_dir
    assert report["removed"] == list(maintenance._SINGLETONS)
    assert all(not os.path.lexists(profile / name) for name in maintenance._SINGLETONS)
    assert (profile / "Default/Cookies").read_bytes() == b"private cookies"
    assert (profile / "Local State").read_bytes() == b"private state"
    assert (profile / "OtherLink").is_symlink()
    audit = Path(report["audit_report"])
    assert audit.parent == stale_profile.settings.state_dir
    assert stat.S_IMODE(audit.stat().st_mode) == 0o600
    assert json.loads(audit.read_text()) == report


@pytest.mark.parametrize("owner", ["foreign-host-2147483647", "unknown", "host-abc", "host-0",
                                    "host--1", "../host-999", "host-99999999999999999999",
                                    "host-01", "host-１２３", "host-2147483648"])
def test_repair_refuses_foreign_or_malformed_owner(stale_profile, owner):
    lock = stale_profile.settings.profile_dir / "SingletonLock"
    lock.unlink()
    lock.symlink_to(owner)
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and not report["applied"]
    assert_singletons_present(stale_profile)


def test_repair_refuses_any_live_pid_even_unrelated(stale_profile, monkeypatch):
    monkeypatch.setattr(psutil, "pid_exists", lambda pid: True)
    assert not repair_profile_lock(stale_profile, apply=True)["ok"]
    assert_singletons_present(stale_profile)


def test_repair_refuses_competing_lease(stale_profile):
    with ProfileLease(stale_profile.settings.profile_dir):
        report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and "owns" in report["reason"]
    assert_singletons_present(stale_profile)


@pytest.mark.parametrize("form", ["equals", "two", "relative", "alias"])
def test_repair_refuses_process_using_profile(stale_profile, monkeypatch, form):
    profile = stale_profile.settings.profile_dir
    if form == "alias":
        alias = profile.parent / "profile-alias"
        alias.symlink_to(profile, target_is_directory=True)
        args = ["chrome", f"--user-data-dir={alias}"]
    elif form == "relative":
        args = ["chrome", "--user-data-dir", "profile"]
    elif form == "two":
        args = ["chrome", "--user-data-dir", str(profile)]
    else:
        args = ["chrome", f"--user-data-dir={profile}"]
    process = SimpleNamespace(cmdline=lambda: args, cwd=lambda: str(profile.parent))
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([process]))
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and "Active profile" in report["reason"]
    assert_singletons_present(stale_profile)


@pytest.mark.parametrize("where", ["iterate", "cmdline", "cwd", "pid"])
def test_repair_fails_closed_on_process_access_errors(stale_profile, monkeypatch, where):
    def denied(*args):
        raise psutil.AccessDenied(pid=123)
    process = SimpleNamespace(cmdline=denied if where == "cmdline" else
                              lambda: ["chrome", "--user-data-dir", "relative"], cwd=denied)
    monkeypatch.setattr(psutil, "process_iter", denied if where == "iterate" else lambda: iter([process]))
    if where == "pid":
        monkeypatch.setattr(psutil, "pid_exists", denied)
    assert not repair_profile_lock(stale_profile, apply=True)["ok"]
    assert_singletons_present(stale_profile)


@pytest.mark.parametrize("name", maintenance._SINGLETONS)
def test_repair_refuses_regular_singleton_files(stale_profile, name):
    path = stale_profile.settings.profile_dir / name
    path.unlink()
    path.write_bytes(b"must preserve")
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and not report["applied"]
    assert path.read_bytes() == b"must preserve"
    assert all(os.path.lexists(stale_profile.settings.profile_dir / item) for item in maintenance._SINGLETONS)


def test_repair_refuses_socket_cookie_without_lock(stale_profile):
    (stale_profile.settings.profile_dir / "SingletonLock").unlink()
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and not report["applied"]
    assert (stale_profile.settings.profile_dir / "SingletonSocket").is_symlink()
    assert (stale_profile.settings.profile_dir / "SingletonCookie").is_symlink()


@pytest.mark.parametrize("name", maintenance._SINGLETONS)
@pytest.mark.parametrize("change", ["target", "same_target", "new_file", "regular"])
def test_repair_rechecks_snapshot_after_process_scan(stale_profile, monkeypatch, change, name):
    calls = 0
    def processes():
        nonlocal calls
        calls += 1
        if calls == 2:
            path = stale_profile.settings.profile_dir / name
            if change == "new_file":
                path.unlink()
            else:
                old = os.readlink(path)
                path.unlink()
                if change == "regular":
                    path.write_text("keep")
                else:
                    path.symlink_to(old if change == "same_target" else "changed")
        return iter([])
    monkeypatch.setattr(psutil, "process_iter", processes)
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and not report["applied"] and report["removed"] == []
    assert os.path.lexists(stale_profile.settings.profile_dir / "Default/Cookies")
    assert all(os.path.lexists(stale_profile.settings.profile_dir / item)
               for item in maintenance._SINGLETONS if item != name)


def test_repair_rechecks_owner_pid_before_apply(stale_profile, monkeypatch):
    scans = 0
    def processes():
        nonlocal scans
        scans += 1
        return iter([])
    monkeypatch.setattr(psutil, "process_iter", processes)
    monkeypatch.setattr(psutil, "pid_exists", lambda pid: scans >= 2)
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and not report["applied"]
    assert_singletons_present(stale_profile)


@pytest.mark.parametrize("which", ["profile", "ancestor", "state"])
def test_repair_refuses_path_symlinks(stale_profile, which):
    profile = stale_profile.settings.profile_dir
    alias = profile.parent / "alias"
    if which == "state":
        target = profile.parent / "real-state"
        target.mkdir()
        alias.symlink_to(target, target_is_directory=True)
        stale_profile.settings.state_dir = alias
    elif which == "ancestor":
        alias.symlink_to(profile.parent, target_is_directory=True)
        stale_profile.settings.profile_dir = alias / profile.name
    else:
        alias.symlink_to(profile, target_is_directory=True)
        stale_profile.settings.profile_dir = alias
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and not report["applied"]
    assert all((profile / name).is_symlink() for name in maintenance._SINGLETONS)


def test_recover_refuses_two_argument_process(stale_profile, monkeypatch):
    store = Store(stale_profile.settings.state_dir)
    stale_profile.store = store
    result, _ = store.create_task(TaskRequest(goal="read"))
    result.status = Status.RUNNING
    store.update(result)
    run = stale_profile.settings.state_dir / "runs" / result.run_id
    run.mkdir(parents=True)
    (run / "owner.json").write_text(json.dumps({"pid": 2147483647, "created": 0}))
    process = SimpleNamespace(cmdline=lambda: ["chrome", "--user-data-dir",
                                               str(stale_profile.settings.profile_dir)])
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([process]))
    report = recover(stale_profile)
    assert report["recovered"] == [] and report["manual_review"]
    assert store.get(result.run_id).status == Status.RUNNING


def test_repair_refuses_foreign_symlink_uid(stale_profile, monkeypatch):
    real_stat = maintenance.os.stat
    def foreign_stat(path, *args, **kwargs):
        info = real_stat(path, *args, **kwargs)
        if path == "SingletonLock":
            return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1)
        return info
    monkeypatch.setattr(maintenance.os, "stat", foreign_stat)
    assert not repair_profile_lock(stale_profile, apply=True)["ok"]
    assert_singletons_present(stale_profile)


def test_repair_refuses_profile_directory_replacement(stale_profile, monkeypatch):
    calls = 0
    profile = stale_profile.settings.profile_dir
    moved = profile.parent / "moved-profile"
    def processes():
        nonlocal calls
        calls += 1
        if calls == 2:
            profile.rename(moved)
            profile.symlink_to(moved, target_is_directory=True)
        return iter([])
    monkeypatch.setattr(psutil, "process_iter", processes)
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and not report["applied"]
    assert all((moved / name).is_symlink() for name in maintenance._SINGLETONS)


def test_repair_refuses_new_profile_process_before_apply(stale_profile, monkeypatch):
    calls = 0
    process = SimpleNamespace(cmdline=lambda: ["chrome", "--user-data-dir",
                                               str(stale_profile.settings.profile_dir)])
    def processes():
        nonlocal calls
        calls += 1
        return iter([] if calls == 1 else [process])
    monkeypatch.setattr(psutil, "process_iter", processes)
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and not report["applied"]
    assert_singletons_present(stale_profile)


def test_repair_refuses_without_writable_audit(stale_profile, monkeypatch):
    def denied(*args):
        raise PermissionError("synthetic audit denial")
    monkeypatch.setattr(maintenance.os, "fsync", denied)
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and not report["applied"]
    assert_singletons_present(stale_profile)


def test_repair_reports_partial_removal_and_preserves_lock(stale_profile, monkeypatch):
    unlink = maintenance.os.unlink
    def deny_cookie(path, *args, **kwargs):
        if path == "SingletonCookie":
            raise PermissionError("synthetic unlink denial")
        return unlink(path, *args, **kwargs)
    monkeypatch.setattr(maintenance.os, "unlink", deny_cookie)
    report = repair_profile_lock(stale_profile, apply=True)
    assert not report["ok"] and report["applied"]
    assert report["removed"] == ["SingletonSocket"]
    assert (stale_profile.settings.profile_dir / "SingletonLock").is_symlink()
    assert (stale_profile.settings.profile_dir / "SingletonCookie").is_symlink()
    assert json.loads(Path(report["audit_report"]).read_text()) == report


def test_recover_fails_closed_when_process_inspection_denied(stale_profile, monkeypatch):
    (stale_profile.settings.state_dir / "runs").mkdir(parents=True)
    def denied():
        raise psutil.AccessDenied(pid=123)
    monkeypatch.setattr(psutil, "process_iter", denied)
    report = recover(stale_profile)
    assert not report["recovered"] and report["manual_review"]


async def test_repair_cli_preview_apply_and_refusal(stale_profile, monkeypatch, capsys):
    import brocode.runtime
    from brocode.cli import dispatch, parser
    monkeypatch.setattr(brocode.runtime, "Runtime", lambda: stale_profile)
    assert await dispatch(parser().parse_args(["repair-profile-lock"])) == 0
    assert json.loads(capsys.readouterr().out)["applied"] is False
    assert await dispatch(parser().parse_args(["repair-profile-lock", "--apply"])) == 0
    assert json.loads(capsys.readouterr().out)["applied"] is True
    assert await dispatch(parser().parse_args(["repair-profile-lock", "--apply"])) == 1
    assert not json.loads(capsys.readouterr().out)["ok"]
