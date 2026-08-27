from pydantic import BaseModel, Field, HttpUrl
from typing import Optional
from datetime import datetime
from .scan import RiskLevel

class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to scan")

class URLFlag(BaseModel):
    flag: str
    description: str
    severity: float = Field(..., ge=0, le=1)

class URLScanResult(BaseModel):
    id: Optional[str] = None
    url: str
    risk_score: float = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    flags: list[URLFlag] = Field(default_factory=list)
    domain_info: dict = Field(default_factory=dict)
    explanation: str
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
