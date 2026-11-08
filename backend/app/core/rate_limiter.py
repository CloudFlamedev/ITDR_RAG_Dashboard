import time
import logging
import threading
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class BaseRateLimiter(ABC):
    """Abstract interface for rate limiters."""

    @abstractmethod
    def is_rate_limited(self, key: str) -> Tuple[bool, int]:
        """Check if key has exceeded limits. Returns (is_limited, retry_after_seconds)."""
        pass

    @abstractmethod
    def record_failed_attempt(self, key: str) -> None:
        """Record a failed attempt for key."""
        pass

    @abstractmethod
    def reset(self, key: str) -> None:
        """Reset history for key."""
        pass


class InMemoryRateLimiter(BaseRateLimiter):
    """
    Thread-safe in-memory sliding window rate limiter for single-instance deployments.
    Note: State is local to the container/worker process. For horizontal scaling across
    multiple container instances, configure REDIS_URL to activate RedisRateLimiter.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._attempts: Dict[str, List[float]] = {}

    def is_rate_limited(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            if key in self._attempts:
                self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]
                if not self._attempts[key]:
                    del self._attempts[key]

            attempts = self._attempts.get(key, [])
            if len(attempts) >= self.max_attempts:
                oldest_in_window = attempts[0]
                retry_after = max(1, int(oldest_in_window + self.window_seconds - now))
                return True, retry_after

            return False, 0

    def record_failed_attempt(self, key: str) -> None:
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            if key not in self._attempts:
                self._attempts[key] = []
            self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]
            self._attempts[key].append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


class RedisRateLimiter(BaseRateLimiter):
    """
    Distributed sliding window rate limiter backed by Redis sorted sets (ZSET).
    Enables shared rate-limiting state across horizontally scaled backend replicas.
    """

    def __init__(self, redis_url: str, max_attempts: int = 5, window_seconds: int = 60):
        import redis
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.redis = redis.from_url(redis_url, decode_responses=True)

    def _get_key(self, key: str) -> str:
        return f"ratelimit:login:{key}"

    def is_rate_limited(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        cutoff = now - self.window_seconds
        r_key = self._get_key(key)

        try:
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(r_key, 0, cutoff)
            pipe.zrange(r_key, 0, 0, withscores=True)
            pipe.zcard(r_key)
            _, oldest_entries, count = pipe.execute()

            if count >= self.max_attempts:
                if oldest_entries:
                    oldest_ts = oldest_entries[0][1]
                    retry_after = max(1, int(oldest_ts + self.window_seconds - now))
                else:
                    retry_after = self.window_seconds
                return True, retry_after

            return False, 0
        except Exception as e:
            logger.error(f"Redis rate limiter check error: {e}")
            return False, 0

    def record_failed_attempt(self, key: str) -> None:
        now = time.time()
        cutoff = now - self.window_seconds
        r_key = self._get_key(key)

        try:
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(r_key, 0, cutoff)
            pipe.zadd(r_key, {f"{now}:{time.time_ns()}": now})
            pipe.expire(r_key, self.window_seconds + 5)
            pipe.execute()
        except Exception as e:
            logger.error(f"Redis rate limiter record error: {e}")

    def reset(self, key: str) -> None:
        r_key = self._get_key(key)
        try:
            self.redis.delete(r_key)
        except Exception as e:
            logger.error(f"Redis rate limiter reset error: {e}")


def create_rate_limiter() -> BaseRateLimiter:
    """
    Factory function to initialize rate limiter based on environment configuration.
    Uses RedisRateLimiter if REDIS_URL is configured; otherwise InMemoryRateLimiter.
    """
    max_attempts = settings.RATE_LIMIT_LOGIN_ATTEMPTS
    window_seconds = settings.RATE_LIMIT_WINDOW_SECONDS

    if settings.REDIS_URL and settings.REDIS_URL.strip():
        try:
            logger.info("Initializing distributed RedisRateLimiter for multi-instance deployment...")
            return RedisRateLimiter(
                redis_url=settings.REDIS_URL.strip(),
                max_attempts=max_attempts,
                window_seconds=window_seconds,
            )
        except Exception as e:
            logger.warning(f"Failed to connect to Redis at {settings.REDIS_URL}: {e}. Falling back to in-memory limiter.")

    logger.info("Initializing InMemoryRateLimiter (Single-instance mode). For multi-replica scaling, configure REDIS_URL.")
    return InMemoryRateLimiter(max_attempts=max_attempts, window_seconds=window_seconds)


# Aliases for backward compatibility
LoginRateLimiter = InMemoryRateLimiter
login_rate_limiter = create_rate_limiter()

# Registration and verification protection
registration_rate_limiter = InMemoryRateLimiter(max_attempts=5, window_seconds=60)
verification_rate_limiter = InMemoryRateLimiter(max_attempts=10, window_seconds=60)
