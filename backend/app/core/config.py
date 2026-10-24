from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    """
    Central application configuration loaded from environment variables and .env file.
    Follows 12-factor application methodology. Supports xAI Grok, Groq LLM, Jina AI,
    and Hugging Face embedding providers seamlessly.
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

    # LLM Configuration (supports Groq and xAI Grok)
    XAI_API_KEY: Optional[str] = Field(default=None, description="API Key for Grok or Groq models")
    XAI_API_BASE: str = Field(default="https://api.x.ai/v1", description="LLM API base URL")
    XAI_MODEL: str = Field(default="grok-4.7", description="LLM chat model name")
    XAI_TIMEOUT_SECONDS: int = Field(default=90, description="Timeout in seconds for LLM calls")

    GROQ_API_KEY: Optional[str] = Field(default=None, description="Groq API Key (alternative to XAI_API_KEY)")
    GROQ_API_BASE: str = Field(default="https://api.groq.com/openai/v1", description="Groq API base URL")
    GROQ_MODEL: str = Field(default="openai/gpt-oss-120b", description="Default Groq model")

    # Jina AI Embeddings Configuration
    JINA_API_KEY: Optional[str] = Field(default=None, description="Jina AI API key for embeddings")
    JINA_API_BASE: str = Field(default="https://api.jina.ai/v1", description="Jina AI API base URL")
    JINA_EMBEDDING_MODEL: str = Field(default="jina-embeddings-v3", description="Jina embedding model")

    # Hugging Face Inference API Configuration
    HF_TOKEN: Optional[str] = Field(default=None, description="Hugging Face API token with inference provider access")
    HF_EMBEDDING_MODEL: str = Field(default="BAAI/bge-small-en-v1.5", description="Hugging Face embedding model")
    EMBEDDING_DIMENSIONS: int = Field(default=384, description="Vector dimension of the embedding model")
    HF_TIMEOUT_SECONDS: int = Field(default=60, description="Timeout for embedding inference calls")
    EMBEDDING_BATCH_SIZE: int = Field(default=16, description="Batch size for embedding vector generation")

    # Local Knowledge-Base Caching
    ATTACK_STIX_FILE: str = Field(default="./data/enterprise-attack.json", description="Path to MITRE ATT&CK STIX 2.1 JSON")
    D3FEND_FILE: str = Field(default="./data/d3fend.json", description="Path to MITRE D3FEND ontology JSON")

    @property
    def is_neon(self) -> bool:
        """Check if connected to Neon cloud postgres based on host or query string."""
        return "neon.tech" in self.DATABASE_URL or "sslmode=require" in self.DATABASE_URL

    @property
    def effective_llm_key(self) -> Optional[str]:
        """Returns active LLM key, prioritizing GROQ_API_KEY or XAI_API_KEY."""
        for key in (self.GROQ_API_KEY, self.XAI_API_KEY):
            if key and not key.startswith("replace-") and not key.strip() == "":
                return key.strip()
        return None

    @property
    def is_groq(self) -> bool:
        """Returns True if the active provider is Groq."""
        key = self.effective_llm_key or ""
        base = self.effective_llm_base or ""
        return "groq" in base.lower() or key.startswith("gsk_")

    @property
    def effective_llm_base(self) -> str:
        """Returns API base URL for LLM calls."""
        key = self.effective_llm_key or ""
        if key.startswith("gsk_") or "groq" in self.XAI_API_BASE.lower():
            return "https://api.groq.com/openai/v1"
        return self.XAI_API_BASE or "https://api.x.ai/v1"

    @property
    def effective_llm_model(self) -> str:
        """Returns model name for LLM calls."""
        return self.XAI_MODEL or self.GROQ_MODEL or "grok-4.7"

    @property
    def has_xai_key(self) -> bool:
        """Returns True if any LLM API key is configured."""
        return bool(self.effective_llm_key)

    @property
    def has_jina_key(self) -> bool:
        """Returns True if Jina AI key is configured."""
        return bool(self.JINA_API_KEY and not self.JINA_API_KEY.startswith("replace-") and len(self.JINA_API_KEY.strip()) > 5)

    @property
    def has_hf_token(self) -> bool:
        """Returns True if Hugging Face token is configured."""
        return bool(self.HF_TOKEN and not self.HF_TOKEN.startswith("replace-") and len(self.HF_TOKEN.strip()) > 5)

    @property
    def effective_embedding_provider(self) -> str:
        if self.has_jina_key:
            return "Jina AI"
        if self.has_hf_token:
            return "Hugging Face"
        return "Offline Grounded"

    @property
    def effective_embedding_model(self) -> str:
        if self.has_jina_key:
            return self.JINA_EMBEDDING_MODEL
        return self.HF_EMBEDDING_MODEL


@lru_cache()
def get_settings() -> Settings:
    """Return cached instance of application settings."""
    return Settings()
