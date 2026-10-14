"""Cancellation across the runtime's async ingress and synchronous workers."""

import asyncio
from threading import Event
from time import monotonic

import pytest

from openminion.modules.runtime.sync import await_with_cancel, run_async_compat
from openminion.services.runtime.ingress.gateway_call import _run_coro_sync


@pytest.mark.parametrize("async_caller", [False, True])
def test_turn_timeout_cancels_worker_provider_before_continuation(async_caller):
    entered, stopped = Event(), Event()
    continued = []

    async def provider():
        entered.set()
        try:
            await asyncio.sleep(10)
        finally:
            stopped.set()

    def worker():
        run_async_compat(provider())
        continued.append("late answer")

    def turn():
        return _run_coro_sync(
            lambda: await_with_cancel(asyncio.to_thread(worker), timeout_s=0.15),
            timeout=0.15,
        )

    async def async_turn():
        return turn()

    started = monotonic()
    with pytest.raises(TimeoutError):
        asyncio.run(async_turn()) if async_caller else turn()
    assert monotonic() - started < 1
    assert entered.is_set()
    assert stopped.wait(1)
    assert continued == []
    assert run_async_compat(asyncio.sleep(0, result="next turn")) == "next turn"


def test_explicit_cancel_stops_worker_without_waiting_for_provider():
    cancel, entered, stopped = Event(), Event(), Event()

    async def provider():
        entered.set()
        cancel.set()
        try:
            await asyncio.sleep(10)
        finally:
            stopped.set()

    def worker():
        run_async_compat(provider())
        pytest.fail("cancelled worker continued")

    started = monotonic()
    with pytest.raises(RuntimeError, match="cancelled"):
        _run_coro_sync(
            lambda: await_with_cancel(
                asyncio.to_thread(worker), timeout_s=5, cancel_event=cancel
            ),
            timeout=5,
        )
    assert monotonic() - started < 1
    assert entered.is_set()
    assert stopped.wait(1)


def test_timeout_returns_while_existing_sync_work_finishes():
    release, finished = Event(), Event()
    from openminion.modules.runtime import sync

    def worker():
        try:
            release.wait(2)
            sync.raise_if_cancelled()
            pytest.fail("late synchronous result continued")
        finally:
            finished.set()

    started = monotonic()
    try:
        with pytest.raises(TimeoutError):
            _run_coro_sync(
                lambda: await_with_cancel(asyncio.to_thread(worker), timeout_s=0.1),
                timeout=0.1,
            )
        assert monotonic() - started < 1
    finally:
        release.set()
    assert finished.wait(1)


def test_nested_turn_inherits_parent_cancellation():
    entered, stopped = Event(), Event()

    async def provider():
        entered.set()
        try:
            await asyncio.sleep(10)
        finally:
            stopped.set()

    def child():
        return _run_coro_sync(
            lambda: await_with_cancel(
                asyncio.to_thread(run_async_compat, provider()), timeout_s=5
            ),
            timeout=5,
        )

    with pytest.raises(TimeoutError):
        _run_coro_sync(
            lambda: await_with_cancel(asyncio.to_thread(child), timeout_s=0.15),
            timeout=0.15,
        )
    assert entered.is_set()
    assert stopped.wait(1)


def test_concurrent_turns_do_not_share_cancellation():
    async def scenario():
        results = await asyncio.gather(
            await_with_cancel(asyncio.sleep(1), timeout_s=0.05),
            await_with_cancel(asyncio.sleep(0.1, result="completed"), timeout_s=1),
            return_exceptions=True,
        )
        assert isinstance(results[0], TimeoutError)
        assert results[1] == "completed"

    asyncio.run(scenario())
