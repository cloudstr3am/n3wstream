import sqlite3
import secrets
from datetime import datetime
from typing import Optional
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from config import get_settings
from models import TenantKey, HitRecord

settings = get_settings()
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tenant_keys (
                api_key    TEXT PRIMARY KEY,
                tenant_id  TEXT NOT NULL,
                created_at TEXT NOT NULL,
                active     INTEGER NOT NULL DEFAULT 1,
                note       TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hit_log (
                api_key    TEXT PRIMARY KEY,
                total_hits INTEGER NOT NULL DEFAULT 0,
                last_hit   TEXT NOT NULL
            )
        """)
        conn.commit()


def issue_key(tenant_id: str, note: Optional[str] = None) -> TenantKey:
    api_key = "sk-" + secrets.token_urlsafe(32)
    created_at = datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO tenant_keys (api_key, tenant_id, created_at, active, note) VALUES (?,?,?,1,?)",
            (api_key, tenant_id, created_at, note),
        )
        conn.execute(
            "INSERT OR IGNORE INTO hit_log (api_key, total_hits, last_hit) VALUES (?,0,?)",
            (api_key, created_at),
        )
        conn.commit()
    return TenantKey(api_key=api_key, tenant_id=tenant_id,
                     created_at=datetime.fromisoformat(created_at))


def revoke_key(api_key: str) -> bool:
    with get_db() as conn:
        cur = conn.execute("UPDATE tenant_keys SET active=0 WHERE api_key=?", (api_key,))
        conn.commit()
    return cur.rowcount > 0


def get_tenant(api_key: str) -> Optional[TenantKey]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM tenant_keys WHERE api_key=? AND active=1", (api_key,)
        ).fetchone()
    if not row:
        return None
    return TenantKey(api_key=row["api_key"], tenant_id=row["tenant_id"],
                     created_at=datetime.fromisoformat(row["created_at"]),
                     active=bool(row["active"]), note=row["note"])


def record_hit(api_key: str):
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute(
            """INSERT INTO hit_log (api_key, total_hits, last_hit) VALUES (?,1,?)
               ON CONFLICT(api_key) DO UPDATE SET
               total_hits = total_hits + 1, last_hit = excluded.last_hit""",
            (api_key, now),
        )
        conn.commit()


def get_hit_stats(api_key: str) -> Optional[HitRecord]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM hit_log WHERE api_key=?", (api_key,)).fetchone()
    if not row:
        return None
    return HitRecord(api_key=row["api_key"], total_hits=row["total_hits"],
                     last_hit=datetime.fromisoformat(row["last_hit"]))


def list_hit_stats() -> list[HitRecord]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM hit_log ORDER BY total_hits DESC").fetchall()
    return [HitRecord(api_key=r["api_key"], total_hits=r["total_hits"],
                      last_hit=datetime.fromisoformat(r["last_hit"])) for r in rows]


async def require_tenant(api_key: str = Security(API_KEY_HEADER)) -> TenantKey:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    tenant = get_tenant(api_key)
    if not tenant:
        raise HTTPException(status_code=403, detail="Invalid or revoked API key")
    record_hit(api_key)
    return tenant


async def require_master(api_key: str = Security(API_KEY_HEADER)):
    if api_key != settings.api_master_key:
        raise HTTPException(status_code=403, detail="Master key required")
