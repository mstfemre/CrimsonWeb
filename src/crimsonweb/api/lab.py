"""Inert local fixture: no exploit payloads or external network access."""

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, RedirectResponse

app = FastAPI(title="CrimsonWeb local lab")


@app.get("/")
async def index() -> PlainTextResponse:
    return PlainTextResponse("CrimsonWeb local test target")


@app.get("/hardened")
async def hardened() -> PlainTextResponse:
    return PlainTextResponse(
        "Configured response",
        headers={
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


@app.get("/redirect")
async def redirect() -> RedirectResponse:
    return RedirectResponse("/hardened")


@app.get("/blocked")
async def blocked() -> PlainTextResponse:
    return PlainTextResponse("Access denied fixture", status_code=403)


@app.get("/limited")
async def limited() -> PlainTextResponse:
    return PlainTextResponse(
        "Rate limit fixture", status_code=429, headers={"Retry-After": "60"}
    )
