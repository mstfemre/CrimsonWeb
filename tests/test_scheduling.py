import asyncio

import pytest

from crimsonweb.scheduling import bounded_results


@pytest.mark.asyncio
async def test_limit_and_complete_results():
    active = peak = 0

    async def operation(item):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)
        active -= 1
        return item

    results = [item async for item in bounded_results(range(1000), operation, 7)]
    assert sorted(results) == list(range(1000))
    assert peak <= 7


@pytest.mark.asyncio
async def test_failure_cancels_pending_work():
    active = 0

    async def operation(item):
        nonlocal active
        active += 1
        try:
            await asyncio.sleep(0)
            if item == 0:
                raise RuntimeError("fixture failure")
            await asyncio.sleep(60)
        finally:
            active -= 1

    with pytest.raises(RuntimeError):
        async for _ in bounded_results(range(100), operation, 5):
            pass
    assert active == 0


@pytest.mark.asyncio
async def test_consumer_cancellation_cleans_pending_tasks():
    entered = asyncio.Event()
    active = 0

    async def operation(item):
        nonlocal active
        active += 1
        entered.set()
        try:
            await asyncio.sleep(60)
        finally:
            active -= 1

    async def consume():
        async for _ in bounded_results(range(100), operation, 5):
            pass

    task = asyncio.create_task(consume())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert active == 0
