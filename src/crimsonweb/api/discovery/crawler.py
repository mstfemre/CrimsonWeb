"""Sequential same-origin HTML/OpenAPI observation through the Phase 4A guard."""

import asyncio
import json
import re
from collections import deque
from uuid import uuid4

from ..workspaces.models import AuthorizationRequest
from ..workspaces.policy import evaluate
from .html import FormAnalyzer
from .inventory import ApplicationSurfaceGraph, EndpointInventory
from .models import Evidence
from .openapi import DiscoveryInputError, OpenAPIImporter
from .store import DiscoveryLimit
from .urls import (
    active_url,
    fingerprint,
    masked_path,
    metadata_link,
    metadata_route,
    same_origin,
    sensitive_operation,
)


async def durable(function, *args):
    """A cancelled await must not abandon an in-flight SQLite transaction."""
    pending = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(pending)
    except asyncio.CancelledError:
        await pending
        raise


class DiscoveryHalt(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class AuthorizedCrawler:
    def __init__(self, service, store, worker_id, transport=None):
        self.service, self.store, self.worker_id, self.transport = (
            service,
            store,
            worker_id,
            transport,
        )

    async def screen(self, job, url, method="GET"):
        workspace, policy = await asyncio.to_thread(
            self.service.store.snapshot, job.workspace_id, job.policy_id
        )
        decision = evaluate(
            workspace,
            policy,
            AuthorizationRequest(url=str(url), method=method, category="crawl"),
            self.service.clock(),
        )
        return decision.allowed and not policy.halted_reason

    async def read_body(self, response, maximum):
        encoding = response.headers.get("content-encoding", "identity").lower().strip()
        if encoding != "identity":
            raise DiscoveryLimit("compressed_response_not_processed")
        length = response.headers.get("content-length", "")
        if length.isdigit() and (len(length) > 20 or int(length) > maximum):
            raise DiscoveryLimit("response_too_large")
        result = bytearray()
        async with asyncio.timeout(10):
            if response.is_stream_consumed:
                result.extend(response.content)
                if len(result) > maximum:
                    raise DiscoveryLimit("response_too_large")
            else:
                async for chunk in response.aiter_raw(chunk_size=8192):
                    if len(result) + len(chunk) > maximum:
                        raise DiscoveryLimit("response_too_large")
                    result.extend(chunk)
        return bytes(result)

    @staticmethod
    def mime(response):
        value = (
            response.headers.get("content-type", "").split(";", 1)[0].lower().strip()
        )
        return (
            value
            if re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", value) and len(value) <= 100
            else None
        )

    def evidence(
        self, source, source_fingerprint, status=None, mime=None, size=0, limitations=()
    ):
        identifier = uuid4()
        return Evidence(
            id=identifier,
            ref=f"discovery_evidence:{identifier}",
            source=source,
            timestamp=self.service.clock(),
            source_fingerprint=source_fingerprint,
            status_code=status,
            content_type=mime,
            body_bytes_examined=size,
            limitations=sorted(set(limitations))[:20],
        )

    async def persist(self, job, evidence, endpoints, relations=()):
        relations = list(relations)
        for endpoint in endpoints:
            relations.extend(
                ApplicationSurfaceGraph.endpoint_relations(
                    job.id, endpoint, evidence.ref
                )
            )
        limited = await durable(
            self.store.save_batch,
            job.workspace_id,
            job.id,
            self.worker_id,
            evidence,
            endpoints,
            relations,
        )
        if limited:
            raise DiscoveryLimit(limited)

    async def import_document(self, job, document, base_url=None, evidence=None):
        importer = OpenAPIImporter(job.limits.max_endpoints)
        entries = importer.parse(document, base_url)
        evidence = evidence or self.evidence(
            "openapi_structure",
            importer.source_digest(document),
            limitations=importer.limitations,
        )
        endpoints = [
            EndpointInventory.make(
                job.id, source="openapi", evidence_ref=evidence.ref, **entry
            )
            for entry in entries
        ]
        await self.persist(job, evidence, endpoints)
        await durable(
            self.store.update,
            job.workspace_id,
            job.id,
            self.worker_id,
            None,
            importer.limitations,
        )
        return (
            "partially_completed"
            if "endpoint_limit" in importer.limitations
            else "completed"
        )

    async def run(self, job, seeds):
        root = active_url(seeds[0])
        queue = deque((active_url(seed), 0, None, 0) for seed in seeds)
        seen = set()
        planned = {str(active_url(seed)) for seed in seeds}
        pages = 0
        limitations = set()
        partial = False
        while queue:
            current = await asyncio.to_thread(self.store.get, job.workspace_id, job.id)
            if current.cancel_requested:
                raise DiscoveryLimit("operator_cancelled")
            url, depth, predecessor, redirects = queue.popleft()
            if str(url) in seen:
                if predecessor:
                    limitations.add("redirect_or_link_deduplicated")
                continue
            if pages >= job.limits.max_pages:
                limitations.add("page_limit")
                partial = True
                break
            seen.add(str(url))
            request = AuthorizationRequest(url=str(url), category="crawl")
            evidence = self.evidence("http_metadata", fingerprint(str(url)))
            origin_ref, path, parameters = metadata_route(str(url))
            endpoint = EndpointInventory.make(
                job.id,
                origin_ref,
                path,
                "GET",
                "http_response",
                evidence.ref,
                parameters=parameters,
                observation_status="request_guarded",
            )
            endpoints, relations = [endpoint], []
            next_redirect = None
            # Every actual request, including redirect hops, gets fresh DNS,
            # atomic policy/job budget, cancellation and owner checks here.
            async with self.service.stream(
                job.workspace_id,
                job.policy_id,
                request,
                self.transport,
                discovery_owner=(str(job.id), self.worker_id),
            ) as response:
                endpoint.status_code, endpoint.content_type = (
                    response.status_code,
                    self.mime(response),
                )
                evidence.status_code, evidence.content_type = (
                    endpoint.status_code,
                    endpoint.content_type,
                )
                if response.status_code == 401:
                    endpoint.authentication_indicators.append(
                        "http_401_authentication_required"
                    )
                if "www-authenticate" in response.headers:
                    endpoint.authentication_indicators.append(
                        "www_authenticate_present"
                    )
                if response.status_code in {403, 429}:
                    endpoint.authentication_indicators.append(
                        "http_403_access_denied"
                        if response.status_code == 403
                        else "http_429_rate_limited"
                    )
                    try:
                        await self.persist(job, evidence, endpoints)
                    except DiscoveryLimit:
                        pass  # policy defense stop takes precedence over inventory caps
                    raise DiscoveryHalt(
                        "http_403_access_denied"
                        if response.status_code == 403
                        else "http_429_rate_limited"
                    )
                if predecessor:
                    relations.append(
                        ApplicationSurfaceGraph.relation(
                            job.id,
                            predecessor.id,
                            "redirect",
                            path,
                            evidence.ref,
                            endpoint.id,
                        )
                    )
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        limitations.add("redirect_location_missing")
                        partial = True
                    elif redirects >= job.limits.max_redirects:
                        limitations.add("redirect_limit")
                        partial = True
                    else:
                        try:
                            next_redirect = active_url(location, str(url))
                        except ValueError as exc:
                            await self.persist(job, evidence, endpoints, relations)
                            raise DiscoveryHalt("redirect_url_rejected") from exc
                        if not same_origin(root, next_redirect):
                            await self.persist(job, evidence, endpoints, relations)
                            raise DiscoveryHalt("redirect_origin_change")
                        if "{" in masked_path(
                            next_redirect.path
                        ) or sensitive_operation(next_redirect.path, "GET"):
                            await self.persist(job, evidence, endpoints, relations)
                            raise DiscoveryHalt("redirect_candidate_only")
                elif endpoint.content_type in {
                    "text/html",
                    "application/xhtml+xml",
                } or (
                    endpoint.content_type
                    and (
                        endpoint.content_type == "application/json"
                        or endpoint.content_type.endswith("+json")
                    )
                ):
                    try:
                        body = await self.read_body(response, job.limits.max_body_bytes)
                    except (DiscoveryLimit, TimeoutError):
                        evidence.limitations.append("body_not_processed")
                        await self.persist(job, evidence, endpoints, relations)
                        raise
                    evidence.body_bytes_examined = len(body)
                    if endpoint.content_type in {"text/html", "application/xhtml+xml"}:
                        evidence.source = "html_structure"
                        parser = FormAnalyzer(str(url))
                        parser.feed(body.decode("utf-8", errors="replace"))
                        parser.close()
                        limitations |= parser.limitations
                        for link in parser.links:
                            try:
                                combined = metadata_link(str(url), link)
                                candidate = active_url(
                                    combined.split("?", 1)[0].split("#", 1)[0]
                                )
                                if not same_origin(
                                    root, candidate
                                ) or not await self.screen(job, candidate):
                                    limitations.add("out_of_scope_link_ignored")
                                    continue
                                target_origin, target_path, params = metadata_route(
                                    combined
                                )
                            except ValueError:
                                limitations.add("invalid_link_ignored")
                                continue
                            target = EndpointInventory.make(
                                job.id,
                                target_origin,
                                target_path,
                                "GET",
                                "html_link",
                                evidence.ref,
                                parameters=params,
                            )
                            endpoints.append(target)
                            relations.append(
                                ApplicationSurfaceGraph.relation(
                                    job.id,
                                    endpoint.id,
                                    "link",
                                    target_path,
                                    evidence.ref,
                                    target.id,
                                )
                            )
                            try:
                                active = active_url(link, str(url))
                            except ValueError:
                                limitations.add("query_or_ambiguous_link_metadata_only")
                                continue
                            if "{" in target_path or sensitive_operation(
                                target_path, "GET"
                            ):
                                limitations.add(
                                    "object_or_sensitive_route_metadata_only"
                                )
                            elif str(active) in planned:
                                continue
                            elif depth >= job.limits.max_depth:
                                limitations.add("depth_limit")
                                partial = True
                            elif str(active) not in planned and len(queue) < 500:
                                queue.append((active, depth + 1, None, 0))
                                planned.add(str(active))
                            elif len(queue) >= 500:
                                limitations.add("frontier_limit")
                                partial = True
                        for form in parser.forms:
                            try:
                                action = active_url(form["action"].split("?", 1)[0])
                                if not same_origin(
                                    root, action
                                ) or not await self.screen(job, action):
                                    limitations.add("out_of_scope_form_ignored")
                                    continue
                                form_origin, form_path, params = metadata_route(
                                    form["action"]
                                )
                            except ValueError:
                                limitations.add("invalid_form_ignored")
                                continue
                            record = FormAnalyzer.form_record(form)
                            endpoint.forms.append(record)
                            target = EndpointInventory.make(
                                job.id,
                                form_origin,
                                form_path,
                                form["method"],
                                "html_form",
                                evidence.ref,
                                parameters=[*params, *form["fields"]],
                                authentication_indicators=["password_form_present"]
                                if form["password"]
                                else [],
                            )
                            endpoints.append(target)
                            relations.append(
                                ApplicationSurfaceGraph.relation(
                                    job.id,
                                    endpoint.id,
                                    "form_action",
                                    form_path,
                                    evidence.ref,
                                    target.id,
                                )
                            )
                    else:
                        try:
                            document = json.loads(body)
                        except (ValueError, UnicodeError, RecursionError):
                            document = None
                        if isinstance(document, dict) and (
                            "openapi" in document or "swagger" in document
                        ):
                            try:
                                importer = OpenAPIImporter(job.limits.max_endpoints)
                                entries = importer.parse(document, str(url))
                                endpoints += [
                                    EndpointInventory.make(
                                        job.id,
                                        source="openapi",
                                        evidence_ref=evidence.ref,
                                        **entry,
                                    )
                                    for entry in entries
                                ]
                                evidence.source = "openapi_structure"
                                limitations |= importer.limitations
                            except DiscoveryInputError:
                                limitations.add("invalid_openapi_response")
                await self.persist(job, evidence, endpoints, relations)
            pages += 1
            await durable(
                self.store.update,
                job.workspace_id,
                job.id,
                self.worker_id,
                pages,
                limitations,
            )
            if next_redirect:
                if str(next_redirect) in seen:
                    limitations.add("redirect_loop")
                    partial = True
                else:
                    queue.appendleft((next_redirect, depth, endpoint, redirects + 1))
        await durable(
            self.store.update,
            job.workspace_id,
            job.id,
            self.worker_id,
            pages,
            limitations,
        )
        return (
            "partially_completed"
            if partial or "endpoint_limit" in limitations
            else "completed"
        )
