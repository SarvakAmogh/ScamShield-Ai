from abc import ABC, abstractmethod
from typing import Any

class AnalysisResult:
    def __init__(self, risk_score: float, risk_level: str, indicators: list, explanation: str):
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.indicators = indicators
        self.explanation = explanation

class BaseAnalyzer(ABC):
    """Abstract base class for scam analyzers. Implement this to add new analysis strategies (ML, LLM, etc.)"""

    @abstractmethod
    async def analyze(self, content: str, **kwargs) -> AnalysisResult:
        """Analyze content and return risk assessment."""
        pass

    @staticmethod
    def calculate_risk_level(score: float) -> str:
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        else:
            return "low"
