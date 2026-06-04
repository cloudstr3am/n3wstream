from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class TenantKey(BaseModel):
    api_key: str
    tenant_id: str
    created_at: datetime = datetime.utcnow()
    active: bool = True
    note: Optional[str] = None


class HitRecord(BaseModel):
    api_key: str
    total_hits: int
    last_hit: datetime


class CreateKeyRequest(BaseModel):
    tenant_id: str
    note: Optional[str] = None


class CreateKeyResponse(BaseModel):
    api_key: str
    tenant_id: str
