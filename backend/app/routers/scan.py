from fastapi import APIRouter, HTTPException
from app.models.scan import MessageScanRequest, MessageScanResult
from app.services.scan_service import scan_message, get_recent_scans

router = APIRouter(prefix="/api/v1/scan", tags=["Message Scanning"])

@router.post("/message", response_model=MessageScanResult)
async def scan_message_endpoint(request: MessageScanRequest):
    """Scan a message for scam indicators and return risk assessment."""
    result = await scan_message(request)
    return result

@router.get("/history")
async def get_scan_history(limit: int = 20):
    """Get recent scan results."""
    return await get_recent_scans(limit)
