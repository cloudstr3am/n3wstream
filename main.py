"""
Newstream — S2 API proxy
========================
Authenticated pass-through proxy to S2. That's it.

Every request from a tenant is:
  1. Authenticated via X-API-Key
  2. Hit-counted
  3. Forwarded to S2 with the real S2 token injected
  4. Response streamed back as-is

Tenant never sees S2 URLs, tokens, or basin names.

Routes
------
ANY  /s2/{path:path}        Proxy to S2 (tenant key required)
POST /admin/keys            Issue tenant key  (master key)
DELETE /admin/keys/{key}    Revoke key        (master key)
GET  /admin/keys            List keys         (master key)
GET  /admin/stats           Hit counts        (master key)
GET  /health                Liveness
"""

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse

import auth
from auth import require_tenant, require_master
from config import get_settings
from models import CreateKeyRequest, CreateKeyResponse, TenantKey

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("newstream")
settings = get_settings()

# One shared async client — connection pooling, keep-alives
_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _client
    auth.init_db()
    _client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=5.0))
    yield
    await _client.aclose()


app = FastAPI(title="Newstream", version="0.1.0", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Proxy — forward everything under /s2/* straight to S2
# ---------------------------------------------------------------------------

def _s2_url(path: str, tenant: TenantKey) -> str:
    """
    Map the incoming path to the correct S2 endpoint.

    S2 has two base URLs:
      - Account-level (basins, tokens, metrics):  https://aws.s2.dev/v1/{path}
      - Basin-level   (streams, records):          https://{basin}.b.s2.dev/v1/{path}

    We route basin-level paths automatically so the tenant
    never needs to know the basin name.
    """
    basin_paths = ("streams", "records", "metrics/")
    if any(path.startswith(p) for p in basin_paths):
        return f"https://{settings.s2_basin}.b.s2.dev/v1/{path}"
    return f"{settings.s2_account_endpoint}/{path}"


@app.api_route("/s2/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path: str, request: Request, tenant: TenantKey = Depends(require_tenant)):
    target = _s2_url(path, tenant)

    # Forward all headers except Host and the tenant's API key
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "x-api-key", "authorization")
    }
    # Inject the real S2 token — tenant never sees this
    forward_headers["Authorization"] = f"Bearer {settings.s2_access_token}"

    body = await request.body()

    logger.info(f"[proxy] tenant={tenant.tenant_id} {request.method} /{path}")

    try:
        resp = await _client.request(
            method=request.method,
            url=target,
            headers=forward_headers,
            content=body,
            params=dict(request.query_params),
        )
    except httpx.RequestError as e:
        logger.error(f"[proxy] upstream error: {e}")
        raise HTTPException(status_code=502, detail="Upstream unavailable")

    # Stream response back — preserves SSE / chunked transfer for tailing reads
    return StreamingResponse(
        content=resp.aiter_bytes(),
        status_code=resp.status_code,
        headers={
            k: v for k, v in resp.headers.items()
            if k.lower() not in ("transfer-encoding",)
        },
        media_type=resp.headers.get("content-type"),
    )


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.post("/admin/keys", dependencies=[Depends(require_master)], response_model=CreateKeyResponse)
async def create_key(req: CreateKeyRequest):
    tenant = auth.issue_key(tenant_id=req.tenant_id, note=req.note)
    return CreateKeyResponse(api_key=tenant.api_key, tenant_id=tenant.tenant_id)


@app.delete("/admin/keys/{api_key}", dependencies=[Depends(require_master)])
async def revoke_key(api_key: str):
    if not auth.revoke_key(api_key):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"revoked": api_key}


@app.get("/admin/keys", dependencies=[Depends(require_master)])
async def list_keys():
    with auth.get_db() as conn:
        rows = conn.execute("SELECT api_key, tenant_id, created_at, active, note FROM tenant_keys ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


@app.get("/admin/stats", dependencies=[Depends(require_master)])
async def stats():
    return auth.list_hit_stats()


@app.get("/admin/stats/{api_key}", dependencies=[Depends(require_master)])
async def stats_for_key(api_key: str):
    rec = auth.get_hit_stats(api_key)
    if not rec:
        raise HTTPException(status_code=404, detail="Key not found")
    return rec
