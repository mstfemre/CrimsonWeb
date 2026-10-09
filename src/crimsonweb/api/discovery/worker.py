"""Exclusive local worker lifetime lock, held until all HTTP cleanup has finished."""

import os
import threading
from pathlib import Path
from weakref import WeakKeyDictionary

_MEMORY_LOCKS = WeakKeyDictionary()
_REGISTRY_LOCK = threading.Lock()


class WorkerLock:
    def __init__(self, repository, namespace="discovery"):
        if namespace not in {"discovery", "privacy"}:
            raise ValueError("Unsupported worker namespace")
        self.namespace = namespace
        self.repository = repository
        self.held = False
        self.recovery_pending = False
        self.handle = None
        self.memory_lock = None

    def acquire(self):
        if self.held:
            return True
        database = self.repository.engine.url.database
        if database in {None, "", ":memory:"}:
            with _REGISTRY_LOCK:
                locks = _MEMORY_LOCKS.setdefault(self.repository.engine, {})
                self.memory_lock = locks.setdefault(self.namespace, threading.Lock())
            self.held = self.memory_lock.acquire(blocking=False)
            self.recovery_pending = self.held
            return self.held
        path = Path(database).resolve()
        # Adjacent local lock, not a PID file or time-based lease. PID reuse/heartbeat
        # expiry do not prove death; exclusive OS lock acquisition does.
        self.handle = Path(str(path) + f".{self.namespace}.lock").open("a+b")  # noqa: SIM115 -- lifetime lock, closed only after worker cleanup
        try:
            if self.handle.seek(0, os.SEEK_END) == 0:
                self.handle.write(b"0")
                self.handle.flush()
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.held = True
            self.recovery_pending = True
        except OSError:
            self.handle.close()
            self.handle = None
        return self.held

    def release(self):
        if self.handle:
            # close releases the OS lock, also automatically on process death.
            self.handle.close()
            self.handle = None
        if self.memory_lock and self.held:
            self.memory_lock.release()
        self.held = False
        self.recovery_pending = False
