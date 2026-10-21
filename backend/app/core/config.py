from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    """
    Central application configuration loaded from environment variables and .env file.
    Follows 12-factor application methodology.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "ITDR Platform API"
    APP_VERSION: str = "2.0.0"
    APP_ENV: str = Field(default="development", description="Runtime environment")
    LOG_LEVEL: str = Field(default="INFO", description="Standard logging level")
    DEMO_MODE: bool = Field(default=True, description="Enable deterministic demo telemetry and fallback records")

    # Neon PostgreSQL Database Connection
    DATABASE_URL: str = Field(
        default="postgresql+psycopg://postgres:postgres123@localhost:5432/itdr_platform",
        description="PostgreSQL connection string. In Neon production, must include sslmode=require"
    )

    # xAI Grok Configuration
    XAI_API_KEY: Optional[str] = Field(default=None, description="xAI API Key for Grok models")
    XAI_API_BASE: str = Field(default="https://api.x.ai/v1", description="xAI API base URL")
    XAI_MODEL: str = Field(default="grok-4.7", description="Grok chat model name")
    XAI_TIMEOUT_SECONDS: int = Field(default=90, description="Timeout in seconds for Grok LLM calls")

    # Hugging Face Inference API Configuration
    HF_TOKEN: Optional[str] = Field(default=None, description="Hugging Face API token with inference provider access")
    HF_EMBEDDING_MODEL: str = Field(default="BAAI/bge-small-en-v1.5", description="Hugging Face embedding model")
    EMBEDDING_DIMENSIONS: int = Field(default=384, description="Vector dimension of the embedding model")
    HF_TIMEOUT_SECONDS: int = Field(default=60, description="Timeout for Hugging Face inference calls")
    EMBEDDING_BATCH_SIZE: int = Field(default=16, description="Batch size for embedding vector generation")

    # Local Knowledge-Base Caching
    ATTACK_STIX_FILE: str = Field(default="./data/enterprise-attack.json", description="Path to MITRE ATT&CK STIX 2.1 JSON")
    D3FEND_FILE: str = Field(default="./data/d3fend.json", description="Path to MITRE D3FEND ontology JSON")

    @property
    def is_neon(self) -> bool:
        """Check if connected to Neon cloud postgres based on host or query string."""
        return "neon.tech" in self.DATABASE_URL or "sslmode=require" in self.DATABASE_URL

    @property
    def has_xai_key(self) -> bool:
        """Returns True if a non-placeholder xAI key is configured."""
        return bool(self.XAI_API_KEY and not self.XAI_API_KEY.startswith("replace-"))

    @property
    def has_hf_token(self) -> bool:
        """Returns True if a non-placeholder HF token is configured."""
        return bool(self.HF_TOKEN and not self.HF_TOKEN.startswith("replace-"))


@lru_cache()
def get_settings() -> Settings:
    """Return cached instance of application settings."""
    return Settings()
