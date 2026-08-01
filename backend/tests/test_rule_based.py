import pytest
from app.analyzers.rule_based import RuleBasedAnalyzer

@pytest.fixture
def analyzer():
    return RuleBasedAnalyzer()

# Test scam messages (should return HIGH/CRITICAL risk)
class TestScamDetection:
    async def test_financial_scam(self, analyzer):
        result = await analyzer.analyze("Congratulations! You won ₹50,000! Click here to claim: bit.ly/xyz123")
        assert result.risk_score >= 50
        assert result.risk_level in ("high", "critical")
        assert len(result.indicators) >= 2
        # Should detect financial_lure and suspicious_url
        rule_names = [ind.rule if hasattr(ind, 'rule') else ind['rule'] for ind in result.indicators]
        assert "financial_lure" in rule_names

    async def test_credential_harvesting(self, analyzer):
        result = await analyzer.analyze("Your SBI account is suspended. Share your OTP to verify: 1800-XXX-XXXX")
        assert result.risk_score >= 50
        rule_names = [ind.rule if hasattr(ind, 'rule') else ind['rule'] for ind in result.indicators]
        assert "credential_harvesting" in rule_names

    async def test_urgency_with_threat(self, analyzer):
        result = await analyzer.analyze("URGENT: Legal action will be taken against you. Act now to avoid arrest. Call immediately.")
        assert result.risk_score >= 50
        assert result.risk_level in ("high", "critical")

    async def test_combined_scam_signals(self, analyzer):
        msg = "Congratulations! You won ₹50,000 lottery! Verify your account immediately. Send OTP to claim prize. bit.ly/claim"
        result = await analyzer.analyze(msg)
        assert result.risk_score >= 75
        assert result.risk_level == "critical"
        assert len(result.indicators) >= 3

# Test clean messages (should return LOW risk)
class TestCleanMessages:
    async def test_normal_message(self, analyzer):
        result = await analyzer.analyze("Hey, are we still meeting for coffee at 3pm today?")
        assert result.risk_score < 25
        assert result.risk_level == "low"
        assert len(result.indicators) == 0

    async def test_business_message(self, analyzer):
        result = await analyzer.analyze("Your order #12345 has been shipped. Expected delivery: Tuesday.")
        assert result.risk_score < 25
        assert result.risk_level == "low"

    async def test_legitimate_bank_notification(self, analyzer):
        result = await analyzer.analyze("Transaction of ₹500 successful at Amazon. Balance: ₹10,000.")
        assert result.risk_score < 50  # might trigger some minor signals, but shouldn't be high

# Edge cases
class TestEdgeCases:
    async def test_empty_message(self, analyzer):
        result = await analyzer.analyze("")
        assert result.risk_score == 0
        assert result.risk_level == "low"

    async def test_very_long_message(self, analyzer):
        result = await analyzer.analyze("hello " * 1000)
        assert result.risk_score < 25

    async def test_special_characters(self, analyzer):
        result = await analyzer.analyze("!@#$%^&*()_+-=[]{}|;':,./<>?")
        assert result.risk_score < 25

    async def test_explanation_is_readable(self, analyzer):
        result = await analyzer.analyze("You won a prize! Click bit.ly/xyz to claim now!")
        assert isinstance(result.explanation, str)
        assert len(result.explanation) > 10  # Should be a real explanation

    async def test_risk_score_bounds(self, analyzer):
        """Risk score should always be between 0 and 100."""
        result = await analyzer.analyze("Send OTP now! You won ₹100000! Click bit.ly/x! Urgent! Legal action! Verify KYC! Share PIN!")
        assert 0 <= result.risk_score <= 100
