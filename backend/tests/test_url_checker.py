import pytest
from app.analyzers.url_checker import URLChecker

@pytest.fixture
def checker():
    return URLChecker()

class TestMaliciousURLs:
    def test_ip_based_url(self, checker):
        result = checker.check("http://192.168.1.1/login")
        assert result["risk_score"] >= 50
        flags = [f["flag"] for f in result["flags"]]
        assert "is_ip_based" in flags

    def test_shortened_url(self, checker):
        result = checker.check("https://bit.ly/xyz123")
        assert result["risk_score"] >= 25
        flags = [f["flag"] for f in result["flags"]]
        assert "is_shortened" in flags

    def test_suspicious_tld(self, checker):
        result = checker.check("https://free-prize.xyz/claim")
        assert result["risk_score"] >= 25
        flags = [f["flag"] for f in result["flags"]]
        assert "suspicious_tld" in flags

    def test_typosquatting(self, checker):
        result = checker.check("https://gooogle.com/login")
        assert result["risk_score"] >= 50
        flags = [f["flag"] for f in result["flags"]]
        assert "typosquatting" in flags

    def test_no_https(self, checker):
        result = checker.check("http://example.com")
        flags = [f["flag"] for f in result["flags"]]
        assert "no_https" in flags

    def test_suspicious_path(self, checker):
        result = checker.check("https://some-site.com/verify-account/login")
        flags = [f["flag"] for f in result["flags"]]
        assert "suspicious_path" in flags

    def test_multiple_flags(self, checker):
        result = checker.check("http://192.168.1.1/login/verify-account")
        assert result["risk_score"] >= 60
        assert len(result["flags"]) >= 2

class TestCleanURLs:
    def test_google(self, checker):
        result = checker.check("https://www.google.com")
        assert result["risk_score"] < 25

    def test_github(self, checker):
        result = checker.check("https://github.com/user/repo")
        assert result["risk_score"] < 25

class TestEdgeCases:
    def test_malformed_url(self, checker):
        result = checker.check("not-a-url")
        assert isinstance(result["risk_score"], (int, float))

    def test_empty_url(self, checker):
        result = checker.check("")
        assert isinstance(result["risk_score"], (int, float))

    def test_domain_info_present(self, checker):
        result = checker.check("https://example.com/path")
        assert "domain_info" in result
        assert isinstance(result["domain_info"], dict)

    def test_risk_score_bounds(self, checker):
        result = checker.check("http://192.168.1.1/verify/login/account/banking")
        assert 0 <= result["risk_score"] <= 100
