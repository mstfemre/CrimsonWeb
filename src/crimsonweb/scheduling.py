"""Bounded async scheduling without eagerly allocating one task per port."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


async def bounded_results(
    items: Iterable[T], operation: Callable[[T], Awaitable[R]], limit: int,
) -> AsyncIterator[R]:
    if limit < 1:
        raise ValueError("Task limit must be positive")
    iterator = iter(items)
    pending: set[asyncio.Task[R]] = set()

    def refill() -> None:
        while len(pending) < limit:
            try:
                item = next(iterator)
            except StopIteration:
                break
            pending.add(asyncio.create_task(operation(item)))

    try:
        refill()
        while pending:
            done, _ = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                result = task.result()
                pending.remove(task)
                yield result
            refill()
    finally:
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
