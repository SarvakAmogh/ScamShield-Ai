import re
from app.analyzers.base import BaseAnalyzer, AnalysisResult

class RuleBasedAnalyzer(BaseAnalyzer):
    """
    Rule-based analyzer for detecting scam indicators in messages.
    Uses regex patterns to identify urgency, financial lures, and suspicious requests.
    """
    def __init__(self):
        self.rules = [
            {
                "name": "urgency_pressure",
                "patterns": [r"act now", r"immediately", r"urgent", r"expire", r"limited time", r"hurry", r"don't delay", r"within 24 hours", r"last chance"],
                "description": "Message demands immediate action",
                "severity": 0.7
            },
            {
                "name": "financial_lure",
                "patterns": [r"won ₹", r"won \$", r"won €", r"prize", r"lottery", r"cashback", r"refund", r"reward", r"jackpot", r"congratulations.*won", r"claim your", r"free money"],
                "description": "Promises of unexpected financial gain",
                "severity": 0.85
            },
            {
                "name": "phishing_request",
                "patterns": [r"verify your account", r"click here", r"update kyc", r"confirm your identity", r"suspended", r"verify immediately", r"login to confirm", r"update your details"],
                "description": "Suspicious request for verification or clicking links",
                "severity": 0.9
            },
            {
                "name": "suspicious_url",
                "patterns": [r"bit\.ly", r"tinyurl", r"t\.co", r"goo\.gl", r"http://\d+\.\d+\.\d+\.\d+"],
                "description": "Contains shortened URLs or IP-based links",
                "severity": 0.6
            },
            {
                "name": "pressure_threat",
                "patterns": [r"legal action", r"police", r"arrest", r"court", r"warrant", r"prosecution", r"your account will be", r"will be blocked"],
                "description": "Threatens legal or punitive action",
                "severity": 0.8
            },
            {
                "name": "fake_authority",
                "patterns": [r"RBI", r"SBI", r"income tax", r"IRS", r"customs", r"government", r"ministry", r"TRAI", r"telecom authority"],
                "description": "Impersonates authorities or government bodies",
                "severity": 0.75
            },
            {
                "name": "credential_harvesting",
                "patterns": [r"send otp", r"share otp", r"your otp", r"enter pin", r"password", r"aadhaar", r"pan card", r"bank account", r"credit card number", r"cvv", r"social security"],
                "description": "Requests sensitive personal or financial information",
                "severity": 0.95
            },
            {
                "name": "too_good_to_be_true",
                "patterns": [r"guaranteed", r"risk\.free", r"100%", r"no risk", r"double your", r"earn ₹.*daily", r"earn \$.*daily", r"work from home.*earn"],
                "description": "Offers highly unrealistic guarantees or earnings",
                "severity": 0.7
            }
        ]

    async def analyze(self, content: str, **kwargs) -> AnalysisResult:
        matched_indicators = []
        
        for rule in self.rules:
            for pattern in rule["patterns"]:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    matched_indicators.append({
                        "rule": rule["name"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "matched_text": match.group(0)
                    })
                    break  # Stop at first pattern match per rule to avoid duplicates for the same rule
                    
        raw_score = sum(ind["severity"] * 50 for ind in matched_indicators)
        risk_score = min(100.0, raw_score)
        risk_level = self.calculate_risk_level(risk_score)
        
        if not matched_indicators:
            explanation = "No obvious risk indicators found in the message."
        else:
            rule_names = [ind["rule"].replace('_', ' ') for ind in matched_indicators]
            rule_str = ", ".join(rule_names)
            explanation = f"This message shows {len(matched_indicators)} risk indicator(s): {rule_str}. Risk score: {risk_score:.0f}/100 ({risk_level})."
            
        return AnalysisResult(
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=matched_indicators,
            explanation=explanation
        )
