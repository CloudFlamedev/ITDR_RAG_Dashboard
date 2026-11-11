import os
from typing import Optional
from dotenv import load_dotenv
load_dotenv()

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
        env_file=(".env", "backend/.env"),
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

    # Jina AI Embeddings & Reranker Configuration
    JINA_API_KEY: Optional[str] = Field(default=None, description="Jina AI API key for embeddings and reranker")
    JINA_API_BASE: str = Field(default="https://api.jina.ai/v1", description="Jina AI API base URL")
    JINA_EMBEDDING_MODEL: str = Field(default="jina-embeddings-v3", description="Jina embedding model")
    JINA_RERANK_MODEL: str = Field(default="jina-reranker-v2-base-multilingual", description="Jina AI Reranker model")
    JINA_RERANK_BASE: str = Field(default="https://api.jina.ai/v1/rerank", description="Jina AI Reranker API endpoint")
    RERANK_ENABLED: bool = Field(default=True, description="Enable cross-encoder reranking before LLM context generation")

    # Hugging Face Inference API Configuration
    HF_TOKEN: Optional[str] = Field(default=None, description="Hugging Face API token with inference provider access")
    HF_EMBEDDING_MODEL: str = Field(default="BAAI/bge-small-en-v1.5", description="Hugging Face embedding model")
    EMBEDDING_DIMENSIONS: int = Field(default=384, description="Vector dimension of the embedding model")
    HF_TIMEOUT_SECONDS: int = Field(default=60, description="Timeout for embedding inference calls")
    EMBEDDING_BATCH_SIZE: int = Field(default=16, description="Batch size for embedding vector generation")

    # Local Knowledge-Base Caching
    ATTACK_STIX_FILE: str = Field(default="./data/enterprise-attack.json", description="Path to MITRE ATT&CK STIX 2.1 JSON")
    D3FEND_FILE: str = Field(default="./data/d3fend.json", description="Path to MITRE D3FEND ontology JSON")

    # Authentication & Session Management Configuration
    SESSION_SECRET_KEY: str = Field(
        default="itdr-insecure-dev-session-secret-key-change-in-production-32chars",
        description="HMAC secret key for signing CSRF tokens and OAuth state"
    )
    SESSION_EXPIRE_MINUTES: int = Field(default=720, description="Absolute maximum session lifetime in minutes (12 hours)")
    SESSION_INACTIVITY_MINUTES: int = Field(default=30, description="Inactivity session timeout in minutes (30 minutes)")
    SESSION_COOKIE_NAME: str = Field(default="itdr_session", description="Name of the HTTP-only session cookie")
    SESSION_COOKIE_SECURE: bool = Field(default=False, description="Set Secure flag on cookies (True in production HTTPS)")
    SESSION_COOKIE_SAMESITE: str = Field(default="lax", description="SameSite policy for session cookie (lax or none)")
    CSRF_COOKIE_NAME: str = Field(default="itdr_csrf", description="Name of the readable CSRF cookie for double-submit protection")

    # Frontend and CORS URLs
    FRONTEND_URL: str = Field(default="http://localhost:5173", description="Origin URL of the frontend application")
    CORS_ORIGIN_WHITELIST: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173,https://itdr-rag-dashboard.vercel.app",
        description="Comma-separated list of allowed CORS origins"
    )

    # Social Login / OAuth Configuration
    GOOGLE_CLIENT_ID: Optional[str] = Field(default=None, description="Google OAuth 2.0 / OIDC Client ID")
    GOOGLE_CLIENT_SECRET: Optional[str] = Field(default=None, description="Google OAuth 2.0 Client Secret")
    GOOGLE_REDIRECT_URI: Optional[str] = Field(default=None, description="Google OAuth authorized redirect URI")

    GITHUB_CLIENT_ID: Optional[str] = Field(default=None, description="GitHub OAuth App Client ID")
    GITHUB_CLIENT_SECRET: Optional[str] = Field(default=None, description="GitHub OAuth App Client Secret")
    GITHUB_REDIRECT_URI: Optional[str] = Field(default=None, description="GitHub OAuth authorized redirect URI")

    # Public Registration & Social Sign-up Policies
    PUBLIC_REGISTRATION_ENABLED: bool = Field(
        default=True,
        description="Whether public visitor registration is enabled"
    )
    ALLOW_OAUTH_AUTO_REGISTRATION: bool = Field(
        default=True,
        description="Whether unprovisioned OAuth users are auto-registered with default role"
    )
    DEFAULT_REGISTRATION_ROLE: str = Field(
        default="Demo Analyst",
        description="Default role assigned to newly registered public users"
    )

    # Email Verification & Delivery
    EMAIL_PROVIDER: str = Field(
        default="console",
        description="Email delivery provider: 'console', 'smtp', or 'mock'"
    )
    EMAIL_FROM: str = Field(
        default="no-reply@itdr-platform.local",
        description="Sender email address for verification emails"
    )
    EMAIL_VERIFICATION_EXPIRE_MINUTES: int = Field(
        default=30,
        description="Expiration time in minutes for email verification tokens"
    )
    SMTP_HOST: Optional[str] = Field(default=None, description="SMTP server hostname")
    SMTP_PORT: int = Field(default=587, description="SMTP server port")
    SMTP_USER: Optional[str] = Field(default=None, description="SMTP authentication username")
    SMTP_PASSWORD: Optional[str] = Field(default=None, description="SMTP authentication password")
    SMTP_TLS: bool = Field(default=True, description="Enable STARTTLS for SMTP connections")

    # Usage Limits for Public Demo Analysts
    DAILY_ANALYSIS_LIMIT: int = Field(
        default=5,
        description="Maximum daily GenAI threat modeling executions for Demo Analyst accounts"
    )
    GLOBAL_DAILY_ANALYSIS_LIMIT: int = Field(
        default=100,
        description="Platform-wide daily analysis quota across all public demo users"
    )
    PUBLIC_LLM_ANALYSIS_ENABLED: bool = Field(
        default=True,
        description="Emergency killswitch to disable public GenAI analysis execution"
    )
    MAX_ADVISORY_CHARS: int = Field(
        default=15000,
        description="Maximum character length for input threat advisories"
    )

    RATE_LIMIT_LOGIN_ATTEMPTS: int = Field(default=5, description="Max failed login attempts before temporary throttling")
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, description="Window in seconds for login rate limiting")
    REDIS_URL: Optional[str] = Field(
        default=None,
        description="Redis connection URL for distributed sliding-window rate limiting across multiple backend instances"
    )

    # Langfuse Observability & Telemetry Configuration (v3+)
    LANGFUSE_PUBLIC_KEY: Optional[str] = Field(default=None, description="Langfuse Public Key")
    LANGFUSE_SECRET_KEY: Optional[str] = Field(default=None, description="Langfuse Secret Key")
    LANGFUSE_BASE_URL: str = Field(default="https://us.cloud.langfuse.com", description="Langfuse Base URL")
    LANGFUSE_HOST: Optional[str] = Field(default=None, description="Langfuse Host URL alias")
    LANGFUSE_ENABLED: bool = Field(default=True, description="Enable Langfuse observability layer")

    @property
    def cors_origins(self) -> list[str]:
        """Returns parsed list of allowed CORS origins, automatically including FRONTEND_URL."""
        origins = [o.strip() for o in self.CORS_ORIGIN_WHITELIST.split(",") if o.strip()]
        if self.FRONTEND_URL and self.FRONTEND_URL.strip() not in origins:
            origins.append(self.FRONTEND_URL.strip())
        return list(dict.fromkeys(origins))

    @property
    def normalized_database_url(self) -> str:
        """Ensure database URL is formatted with the modern postgresql+psycopg driver."""
        url = self.DATABASE_URL or ""
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+psycopg://", 1)
        if url.startswith("postgresql://") and not url.startswith("postgresql+"):
            return url.replace("postgresql://", "postgresql+psycopg://", 1)
        return url

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
    def is_production(self) -> bool:
        """Returns True if the application is running in production mode."""
        return self.APP_ENV.lower() in ("production", "prod")

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
        if self.has_hf_token:
            return self.HF_EMBEDDING_MODEL
        return "offline-bge-384"

    @property
    def has_reranker(self) -> bool:
        """Returns True if Jina AI reranker is enabled and configured."""
        return self.RERANK_ENABLED and self.has_jina_key

    @property
    def effective_rerank_model(self) -> str:
        return self.JINA_RERANK_MODEL or "jina-reranker-v2-base-multilingual"

    @property
    def effective_langfuse_host(self) -> str:
        host = self.LANGFUSE_HOST or self.LANGFUSE_BASE_URL or "https://us.cloud.langfuse.com"
        host_str = str(host).strip().rstrip("/")
        if not host_str.startswith("http://") and not host_str.startswith("https://"):
            host_str = f"https://{host_str}"
        return host_str

    @property
    def has_langfuse_credentials(self) -> bool:
        return bool(self.LANGFUSE_PUBLIC_KEY and self.LANGFUSE_SECRET_KEY and self.LANGFUSE_ENABLED)


@lru_cache()
def get_settings() -> Settings:
    """Return cached instance of application settings."""
    return Settings()
