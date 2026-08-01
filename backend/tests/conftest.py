import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, MagicMock

class AsyncIterator:
    def __init__(self, seq):
        self.iter = iter(seq)
    def __aiter__(self):
        return self
    async def __anext__(self):
        try:
            return next(self.iter)
        except StopIteration:
            raise StopAsyncIteration

@pytest.fixture
def mock_db():
    """Mock MongoDB database for tests."""
    db = MagicMock()
    # Mock scans collection
    mock_collection = MagicMock()
    mock_insert_result = MagicMock()
    mock_insert_result.inserted_id = "test_id_123"
    mock_collection.insert_one = AsyncMock(return_value=mock_insert_result)
    mock_collection.find = MagicMock(return_value=MagicMock(
        sort=MagicMock(return_value=MagicMock(
            limit=MagicMock(return_value=AsyncIterator([]))
        ))
    ))
    db.scans = mock_collection
    db.url_scans = mock_collection
    return db

@pytest.fixture
async def client(mock_db):
    """Async test client with mocked database."""
    with patch("app.database.connect_db", new_callable=AsyncMock), \
         patch("app.database.close_db", new_callable=AsyncMock), \
         patch("app.database.get_database", return_value=mock_db):
        from app.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
