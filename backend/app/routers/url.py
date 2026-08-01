from fastapi import APIRouter
from app.models.url import URLScanRequest, URLScanResult
from app.services.scan_service import scan_url

router = APIRouter(prefix="/api/v1/scan", tags=["URL Scanning"])

@router.post("/url", response_model=URLScanResult)
async def scan_url_endpoint(request: URLScanRequest):
    """Scan a URL for phishing/scam indicators."""
    result = await scan_url(request)
    return result
