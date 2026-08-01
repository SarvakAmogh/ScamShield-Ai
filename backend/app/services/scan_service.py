from app.analyzers.rule_based import RuleBasedAnalyzer
from app.analyzers.url_checker import URLChecker
from app.models.scan import MessageScanRequest, MessageScanResult, RiskIndicator, RiskLevel
from app.models.url import URLScanRequest, URLScanResult, URLFlag
from app.database import get_database
from datetime import datetime

rule_analyzer = RuleBasedAnalyzer()
url_checker = URLChecker()

async def scan_message(request: MessageScanRequest) -> MessageScanResult:
    result = await rule_analyzer.analyze(request.message)
    
    indicators = []
    if result.indicators:
        if isinstance(result.indicators[0], dict):
            indicators = [RiskIndicator(**ind) for ind in result.indicators]
        else:
            indicators = result.indicators

    scan_result = MessageScanResult(
        message=request.message,
        source=request.source,
        risk_score=result.risk_score,
        risk_level=RiskLevel(result.risk_level),
        indicators=indicators,
        explanation=result.explanation,
        scanned_at=datetime.utcnow()
    )
    # Persist to MongoDB
    try:
        db = get_database()
        if db is not None:
            doc = scan_result.model_dump()
            insert_result = await db.scans.insert_one(doc)
            scan_result.id = str(insert_result.inserted_id)
    except Exception:
        pass  # DB persistence is best-effort for now
    return scan_result

async def scan_url(request: URLScanRequest) -> URLScanResult:
    result = url_checker.check(request.url)
    scan_result = URLScanResult(
        url=request.url,
        risk_score=result["risk_score"],
        risk_level=RiskLevel(result["risk_level"]),
        flags=[URLFlag(**f) for f in result["flags"]],
        domain_info=result["domain_info"],
        explanation=result["explanation"],
        scanned_at=datetime.utcnow()
    )
    try:
        db = get_database()
        if db is not None:
            doc = scan_result.model_dump()
            insert_result = await db.url_scans.insert_one(doc)
            scan_result.id = str(insert_result.inserted_id)
    except Exception:
        pass
    return scan_result

async def get_recent_scans(limit: int = 20) -> list[dict]:
    try:
        db = get_database()
        if db is not None:
            cursor = db.scans.find().sort("scanned_at", -1).limit(limit)
            scans = []
            async for doc in cursor:
                doc["id"] = str(doc.pop("_id"))
                scans.append(doc)
            return scans
    except Exception:
        pass
    return []
