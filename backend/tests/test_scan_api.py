import pytest

class TestMessageScanEndpoint:
    async def test_scan_scam_message(self, client):
        response = await client.post("/api/v1/scan/message", json={
            "message": "You won ₹50,000! Send OTP to claim prize now!",
            "source": "sms"
        })
        assert response.status_code == 200
        data = response.json()
        assert "risk_score" in data
        assert "risk_level" in data
        assert "indicators" in data
        assert "explanation" in data
        assert data["risk_score"] >= 50

    async def test_scan_clean_message(self, client):
        response = await client.post("/api/v1/scan/message", json={
            "message": "See you at dinner tonight!"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] < 25
        assert data["risk_level"] == "low"

    async def test_empty_message_rejected(self, client):
        response = await client.post("/api/v1/scan/message", json={
            "message": ""
        })
        assert response.status_code == 422  # Validation error

    async def test_missing_message_rejected(self, client):
        response = await client.post("/api/v1/scan/message", json={})
        assert response.status_code == 422

    async def test_response_schema(self, client):
        response = await client.post("/api/v1/scan/message", json={
            "message": "Test message"
        })
        data = response.json()
        assert isinstance(data["risk_score"], (int, float))
        assert data["risk_level"] in ["low", "medium", "high", "critical"]
        assert isinstance(data["indicators"], list)
        assert isinstance(data["explanation"], str)

class TestHealthEndpoint:
    async def test_health(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
