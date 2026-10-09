"""Durable job manager: one cooperating local worker, serial guarded observations."""

import asyncio
from uuid import uuid4

import httpx
from sqlalchemy.exc import SQLAlchemyError

from ..workspaces.models import AuthorizationRequest
from ..workspaces.service import AuthorizationDenied
from ..workspaces.store import Conflict
from .crawler import AuthorizedCrawler, DiscoveryHalt, durable
from .openapi import DiscoveryInputError, OpenAPIImporter
from .store import DiscoveryEvidenceStore, DiscoveryLimit
from .urls import active_url, masked_path, same_origin, sensitive_operation
from .worker import WorkerLock


class DiscoveryJobManager:
    def __init__(self, repository, workspace_service, transport=None):
        self.service = workspace_service
        self.store = DiscoveryEvidenceStore(repository)
        self.transport = transport
        self.worker_id = str(uuid4())
        self.worker_lock = WorkerLock(repository)
        self.tasks = {}
        self.gate = asyncio.Semaphore(1)
        self.submission = asyncio.Lock()
        self.closed = False

    async def startup(self):
        if self.worker_lock.held:
            return 0
        if self.worker_lock.acquire():
            try:
                return await durable(
                    self.store.recover, self.service.clock(), self.worker_lock
                )
            except BaseException:
                self.worker_lock.release()
                raise
        return 0

    def available(self):
        if self.closed or not self.worker_lock.held:
            raise Conflict("Discovery worker unavailable")

    async def start_crawl(self, workspace_id, payload):
        self.available()
        try:
            seeds = list(dict.fromkeys(str(active_url(s)) for s in payload.seeds))
        except ValueError as exc:
            raise DiscoveryInputError("invalid_seed_url") from exc
        root = active_url(seeds[0])
        if any(not same_origin(root, active_url(s)) for s in seeds):
            raise DiscoveryInputError("seeds_must_share_origin")
        if any(
            "{" in masked_path(active_url(s).path)
            or sensitive_operation(active_url(s).path, "GET")
            for s in seeds
        ):
            raise DiscoveryInputError("object_or_sensitive_seed_not_requested")
        revision = None
        for seed in seeds:
            decision = await self.service.preflight(
                workspace_id,
                payload.policy_id,
                AuthorizationRequest(url=seed, category="crawl"),
            )
            if not decision.allowed:
                raise AuthorizationDenied(decision.reason)
            if revision is not None and revision != decision.policy_revision:
                raise Conflict("Policy changed")
            revision = decision.policy_revision
        return await self.enqueue(
            workspace_id, "crawl", payload.limits, seeds, payload.policy_id, revision
        )

    async def import_openapi(self, workspace_id, payload):
        self.available()
        # Validate before queuing; no DNS, no server or $ref fetch.
        OpenAPIImporter(payload.limits.max_endpoints).parse(
            payload.document, payload.base_url
        )
        revision = None
        if payload.policy_id:
            _, policy = await asyncio.to_thread(
                self.service.store.snapshot, workspace_id, payload.policy_id
            )
            revision = policy.revision
        return await self.enqueue(
            workspace_id,
            "openapi_import",
            payload.limits,
            (payload.document, payload.base_url),
            payload.policy_id,
            revision,
        )

    async def enqueue(self, workspace_id, mode, limits, data, policy_id, revision):
        async with self.submission:
            self.available()
            if len(self.tasks) >= 8:
                raise Conflict("Discovery queue full")
            job = await durable(
                self.store.create,
                workspace_id,
                mode,
                limits,
                self.service.clock(),
                policy_id,
                revision,
                data if mode == "crawl" else (),
            )
            key = (str(workspace_id), str(job.id))
            task = asyncio.create_task(self.execute(job, data))
            self.tasks[key] = task

            def done(future):
                self.tasks.pop(key, None)
                if not future.cancelled():
                    # Consume exceptions without raw data/traceback logging.
                    future.exception()

            task.add_done_callback(done)
            return job

    async def execute(self, job, data):
        status, reason = "failed", "worker_error"
        try:
            async with self.gate:
                claimed = await durable(
                    self.store.claim,
                    job.workspace_id,
                    job.id,
                    self.worker_id,
                    self.service.clock(),
                )
                if claimed is None:
                    return
                crawler = AuthorizedCrawler(
                    self.service, self.store, self.worker_id, self.transport
                )
                if job.mode == "crawl":
                    status = await crawler.run(claimed, data)
                else:
                    status = await crawler.import_document(claimed, data[0], data[1])
                reason = None if status == "completed" else "discovery_limits_reached"
        except asyncio.CancelledError:
            status, reason = "cancelled", "operator_cancelled"
        except DiscoveryLimit as exc:
            status, reason = (
                (
                    "cancelled"
                    if exc.code == "operator_cancelled"
                    else "partially_completed"
                ),
                exc.code,
            )
        except (AuthorizationDenied, DiscoveryHalt) as exc:
            reason = exc.reason if isinstance(exc, AuthorizationDenied) else exc.code
            status = (
                "partially_completed"
                if reason
                in {
                    "budget_exhausted",
                    "rate_limit_exceeded",
                    "concurrency_exceeded",
                    "discovery_budget_exhausted",
                }
                else "cancelled"
                if reason == "discovery_cancelled"
                else "halted_by_policy"
            )
        except DiscoveryInputError as exc:
            status, reason = "failed", exc.code
        except (httpx.HTTPError, TimeoutError, OSError):
            status, reason = "partially_completed", "network_or_body_timeout"
        except (SQLAlchemyError, Conflict):
            status, reason = "failed", "storage_or_ownership_error"
        finally:
            # Do not publish completion before all guard/response contexts exited.
            await durable(
                self.store.finish,
                job.workspace_id,
                job.id,
                self.worker_id,
                status,
                reason,
                self.service.clock(),
            )

    async def cancel(self, workspace_id, job_id):
        await durable(self.store.cancel, workspace_id, job_id, self.service.clock())
        task = self.tasks.get((str(workspace_id), str(job_id)))
        if task:
            if not task.cancelling():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return await asyncio.to_thread(self.store.get, workspace_id, job_id)

    async def shutdown(self):
        self.closed = True
        pending = list(self.tasks.items())
        try:
            for (workspace_id, job_id), task in pending:
                await durable(
                    self.store.cancel, workspace_id, job_id, self.service.clock()
                )
                if not task.cancelling():
                    task.cancel()
            await asyncio.gather(*(task for _, task in pending), return_exceptions=True)
        finally:
            # If storage errors prevented cancellation, still stop/join every
            # coroutine before releasing proof of ownership to another process.
            for _, task in pending:
                if not task.done() and not task.cancelling():
                    task.cancel()
            await asyncio.gather(*(task for _, task in pending), return_exceptions=True)
            self.worker_lock.release()
