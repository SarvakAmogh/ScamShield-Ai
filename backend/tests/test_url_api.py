import pytest

class TestURLScanEndpoint:
    async def test_scan_suspicious_url(self, client):
        response = await client.post("/api/v1/scan/url", json={
            "url": "http://192.168.1.1/login/verify"
        })
        assert response.status_code == 200
        data = response.json()
        assert "risk_score" in data
        assert "risk_level" in data
        assert "flags" in data
        assert data["risk_score"] >= 50

    async def test_scan_clean_url(self, client):
        response = await client.post("/api/v1/scan/url", json={
            "url": "https://www.google.com"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] < 25

    async def test_empty_url_rejected(self, client):
        response = await client.post("/api/v1/scan/url", json={
            "url": ""
        })
        assert response.status_code == 422

    async def test_missing_url_rejected(self, client):
        response = await client.post("/api/v1/scan/url", json={})
        assert response.status_code == 422

    async def test_response_schema(self, client):
        response = await client.post("/api/v1/scan/url", json={
            "url": "https://example.com"
        })
        data = response.json()
        assert isinstance(data["risk_score"], (int, float))
        assert data["risk_level"] in ["low", "medium", "high", "critical"]
        assert isinstance(data["flags"], list)
        assert isinstance(data["explanation"], str)
        assert isinstance(data["domain_info"], dict)
