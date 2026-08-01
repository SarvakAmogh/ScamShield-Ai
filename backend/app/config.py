from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "scamshield"
CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5500", "http://127.0.0.1:5500", "https://scam-shield-ai-bny7.vercel.app"]
    APP_NAME: str = "ScamShield AI"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

settings = Settings()
