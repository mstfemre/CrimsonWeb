"""Synthetic scheduler allocation benchmark; sends no network traffic."""

import asyncio
import time
import tracemalloc

from crimsonweb.scheduling import bounded_results


async def operation(item):
    await asyncio.sleep(0)
    return item


async def main():
    for mode in ("eager", "bounded"):
        tracemalloc.start()
        started = time.perf_counter()
        if mode == "eager":
            results = await asyncio.gather(*(operation(i) for i in range(20_000)))
        else:
            results = [r async for r in bounded_results(range(20_000), operation, 100)]
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        print(f"{mode}: count={len(results)} peak={peak / 1048576:.2f} MiB "
              f"time={time.perf_counter() - started:.3f}s")


if __name__ == "__main__":
    asyncio.run(main())
