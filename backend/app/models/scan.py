from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class MessageScanRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000, description="Message text to scan")
    source: Optional[str] = Field(None, description="Source: sms, whatsapp, email, etc.")

class RiskIndicator(BaseModel):
    rule: str = Field(..., description="Rule name that triggered")
    description: str = Field(..., description="Human-readable explanation")
    severity: float = Field(..., ge=0, le=1, description="Severity weight 0-1")
    matched_text: Optional[str] = Field(None, description="The text that matched the rule")

class MessageScanResult(BaseModel):
    id: Optional[str] = Field(None, description="Database record ID")
    message: str
    source: Optional[str] = None
    risk_score: float = Field(..., ge=0, le=100, description="Overall risk score 0-100")
    risk_level: RiskLevel
    indicators: list[RiskIndicator] = []
    explanation: str = Field(..., description="Human-readable summary")
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
