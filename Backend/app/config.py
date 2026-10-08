import os
from typing import List

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:  # pragma: no cover
    from pydantic import BaseSettings  # type: ignore
    SettingsConfigDict = None  # type: ignore

from pydantic import Field


_ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_ENV_PATH = os.path.join(_ROOT_DIR, ".env")


class Settings(BaseSettings):
    if SettingsConfigDict is not None:
        model_config = SettingsConfigDict(
            env_file=(_ENV_PATH, ".env", "../.env"),
            env_file_encoding="utf-8",
            extra="allow"
        )
    else:
        class Config:
            env_file = (_ENV_PATH, ".env", "../.env")
            env_file_encoding = "utf-8"
            extra = "allow"
    APP_NAME: str = "CYBERSCOPE"
    APP_ENV: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Database: SQLite default for friction-free local execution; supports PostgreSQL
    DATABASE_URL: str = "sqlite:///./cyberscope.db"

    # Graph layer: networkx (in-memory synchronized with relational store) or neo4j
    GRAPH_BACKEND: str = "networkx"
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "cyberscope_neo4j"

    # AI Provider: fallback (deterministic explainable expert engine) or openai or nvidia
    AI_PROVIDER: str = "fallback"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    OPENAI_API_BASE: str = "https://api.openai.com/v1"
    NVIDIA_API_KEY: str = ""
    NVIDIA_MODEL: str = "meta/llama-3.2-11b-vision-instruct"

    # Detection & Analysis Thresholds
    BURST_WINDOW_MINUTES: int = 15
    BURST_TRANSACTION_COUNT: int = 4
    FAN_OUT_THRESHOLD: int = 3
    FAN_IN_THRESHOLD: int = 3
    CIRCULAR_FLOW_MAX_HOPS: int = 5
    DORMANCY_DAYS_THRESHOLD: int = 30
    # Supabase Authentication & Project Settings
    SUPABASE_URL: str = ""
    SUPABASE_ANON_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""
    SUPABASE_JWT_SECRET: str = ""
    REQUIRE_AUTH: bool = False

    # Email / SMTP Configuration
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "noreply@cyberscope.io"
    SMTP_FROM_NAME: str = "CyberScope Security"
    SMTP_USE_TLS: bool = True
    SMTP_USE_SSL: bool = False
    SMTP_TIMEOUT_SECONDS: int = 10

    # SMS Configuration (supports "twilio", "fast2sms", "webhook", "mock")
    SMS_PROVIDER: str = "twilio"
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_FROM_NUMBER: str = ""
    TWILIO_MESSAGING_SERVICE_SID: str = ""
    FAST2SMS_API_KEY: str = ""
    SMS_WEBHOOK_URL: str = ""

    # Dispatch & Verification Testing
    VERIFICATION_MOCK_DISPATCH: bool = False


settings = Settings()
