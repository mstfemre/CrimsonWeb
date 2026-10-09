"""Discovery fixtures never perform real HTTP or DNS."""

import asyncio

import httpx
from workspace_helpers import policy, seeded

from crimsonweb.api.discovery.models import CrawlRequest, OpenAPIImportRequest
from crimsonweb.api.discovery.service import DiscoveryJobManager


def crawl_policy(**changes):
    original = policy().model_dump()
    original["target_scope"]["allowed_categories"] = ["web_observation", "crawl"]
    original.update(changes)
    return policy(**original)


def setup(handler=None, configuration=None, resolver=None, url="sqlite://"):
    repo, service, workspace, record = seeded(
        url, configuration=configuration or crawl_policy(), resolver=resolver
    )
    manager = DiscoveryJobManager(
        repo,
        service,
        httpx.MockTransport(
            handler
            or (
                lambda request: httpx.Response(
                    200, headers={"content-type": "text/html"}, content=b"<html></html>"
                )
            )
        ),
    )
    return repo, service, workspace, record, manager


async def wait(manager, workspace_id, job_id):
    task = manager.tasks.get((str(workspace_id), str(job_id)))
    if task:
        await asyncio.wait_for(asyncio.shield(task), timeout=10)
    return manager.store.get(workspace_id, job_id)


def crawl_request(policy_id, seeds=None, **limits):
    return CrawlRequest(
        policy_id=policy_id, seeds=seeds or ["http://lab.test/"], limits=limits
    )


def spec():
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "https://never-fetch.invalid"}],
        "components": {
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "Object": {
                    "type": "object",
                    "properties": {
                        "owner_id": {"type": "integer", "example": 999},
                        "tenant_id": {"type": ["string", "null"]},
                        "token": {
                            "type": "string",
                            "example": "SYNTHETIC_TOKEN_NOT_RETAINED",
                        },
                    },
                }
            },
        },
        "security": [{"bearer": []}],
        "paths": {
            "/api/objects/{object_id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "object_id",
                            "in": "path",
                            "schema": {"type": "integer"},
                        },
                        {
                            "name": "include",
                            "in": "query",
                            "schema": {"type": "boolean"},
                        },
                    ],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {"schema": {"type": "object"}}
                            }
                        }
                    },
                },
                "delete": {"responses": {}},
            },
            "/api/objects": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Object"}
                            }
                        }
                    },
                    "responses": {},
                }
            },
            "/health": {"get": {"security": [], "responses": {}}},
        },
    }


def import_request(**changes):
    return OpenAPIImportRequest(document=spec(), **changes)
