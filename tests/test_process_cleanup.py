"""Synthetic process ownership tests; no Chrome, network or private profile."""
import asyncio
import os
import signal
import sys

import psutil
import pytest

from brocode.runtime import finish_cleanup, stop_owned_group


async def test_cleanup_stops_child_even_after_leader_exits(tmp_path):
    # A detached session leader exits, leaving a child that ignores SIGTERM.
    pid_file = tmp_path / "child.pid"
    code = """
import os, signal, time, sys
pid = os.fork()
if pid:
    sys.exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open(sys.argv[1], 'w') as stream:
    stream.write(str(os.getpid()))
time.sleep(60)
"""
    unrelated = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time;time.sleep(60)",
                                                     start_new_session=True)
    leader = await asyncio.create_subprocess_exec(sys.executable, "-c", code, str(pid_file),
                                                  start_new_session=True)
    child = None
    try:
        for _ in range(100):
            if pid_file.exists() and pid_file.read_text():
                child = psutil.Process(int(pid_file.read_text()))
                break
            await asyncio.sleep(0.02)
        assert child is not None
        await leader.wait()
        await stop_owned_group(leader, grace=0.1, kill_grace=2)
        assert not child.is_running() or child.status() == psutil.STATUS_ZOMBIE
        assert unrelated.returncode is None
    finally:
        if child is not None:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        if leader.returncode is None:
            os.killpg(leader.pid, signal.SIGKILL)
            await leader.wait()
        unrelated.kill()
        await unrelated.wait()


async def test_repeated_cancellation_cannot_abandon_cleanup():
    entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def cleanup():
        entered.set()
        await release.wait()
        finished.set()

    task = asyncio.create_task(finish_cleanup(cleanup()))
    await entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert finished.is_set()
