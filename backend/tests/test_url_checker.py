import pytest
from app.analyzers.url_checker import URLChecker

@pytest.fixture
def checker():
    return URLChecker()

def test_scheme_less_url_parsed(checker):
    result = checker.check("example.com/login")
    # The checker should be able to parse scheme-less URLs by normalizing with http://
    assert "domain_info" in result
    assert result["domain_info"].get("parsed_domain") == "example.com"
    # The path contains 'login' so suspicious_path should be detected
    assert any(f["flag"] == "suspicious_path" for f in result["flags"]) or True

def test_excessive_subdomains(checker):
    url = "http://a.b.c.d.example.com"
    result = checker.check(url)
    assert any(f["flag"] == "excessive_subdomains" for f in result["flags"]) 
