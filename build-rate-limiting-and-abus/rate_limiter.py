import time
import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, Awaitable, Dict, Any

class Tier(str, Enum):
    FREE = "free"
    STANDARD = "standard"
    PREMIUM = "premium"
    INTERNAL = "internal"

@dataclass
class TierConfig:
    requests: int
    window_seconds: int

TIER_LIMITS: Dict[Tier, TierConfig] = {
    Tier.FREE:      TierConfig(requests=60,   window_seconds=60),
    Tier.STANDARD:  TierConfig(requests=300,  window_seconds=60),
    Tier.PREMIUM:   TierConfig(requests=1000, window_seconds=60),
    Tier.INTERNAL:  TierConfig(requests=5000, window_seconds=60),
}

@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_at: float
    limit: int
    retry_after: Optional[float] = None

class InMemoryStore:
    def __init__(self):
        self._windows: Dict[str, list] = {}

    async def add_and_count(self, key: str, timestamp: float, window_seconds: int) -> int:
        cutoff = timestamp - window_seconds
        entries = self._windows.get(key, [])
        entries = [t for t in entries if t > cutoff]
        entries.append(timestamp)
        self._windows[key] = entries
        return len(entries)

    async def get_count(self, key: str, timestamp: float, window_seconds: int) -> int:
        cutoff = timestamp - window_seconds
        entries = self._windows.get(key, [])
        entries = [t for t in entries if t > cutoff]
        self._windows[key] = entries
        return len(entries)

    async def get_oldest(self, key: str, timestamp: float, window_seconds: int) -> Optional[float]:
        cutoff = timestamp - window_seconds
        entries = self._windows.get(key, [])
        entries = [t for t in entries if t > cutoff]
        self._windows[key] = entries
        return min(entries) if entries else None

class RedisStore:
    def __init__(self, redis_client):
        self._redis = redis_client

    async def add_and_count(self, key: str, timestamp: float, window_seconds: int) -> int:
        rk = f"rl:{key}"
        pipe = self._redis.pipeline()
        pipe.zadd(rk, {str(timestamp): timestamp})
        pipe.zremrangebyscore(rk, "-inf", timestamp - window_seconds)
        pipe.zcard(rk)
        pipe.expire(rk, window_seconds + 1)
        results = await pipe.execute()
        return results[2]

    async def get_count(self, key: str, timestamp: float, window_seconds: int) -> int:
        rk = f"rl:{key}"
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(rk, "-inf", timestamp - window_seconds)
        pipe.zcard(rk)
        results = await pipe.execute()
        return results[1]

    async def get_oldest(self, key: str, timestamp: float, window_seconds: int) -> Optional[float]:
        rk = f"rl:{key}"
        await self._redis.zremrangebyscore(rk, "-inf", timestamp - window_seconds)
        oldest = await self._redis.zrange(rk, 0, 0, withscores=True)
        if oldest:
            return float(oldest[0][1])
        return None

class RateLimiter:
    def __init__(
        self,
        store: Any = None,
        tier_limits: Optional[Dict[Tier, TierConfig]] = None,
        key_prefix: str = "sgate",
        abuse_hook: Optional[Callable[[str, Tier, int], Awaitable[None]]] = None,
    ):
        self._store = store or InMemoryStore()
        self._tier_limits = tier_limits or TIER_LIMITS
        self._key_prefix = key_prefix
        self._abuse_hook = abuse_hook

    def _make_key(self, identity: str, tier: Tier, service: str = "") -> str:
        parts = [self._key_prefix, tier.value, identity]
        if service:
            parts.append(service)
        return ":".join(parts)

    def _get_config(self,? tier: Tier) -> TierConfig:
        return self._tier_limits.get(tier, TIER_LIMITS[Tier.FREE])

    async def check(
        self,
        identity: str,
        tier: Tier = Tier.FREE,
        service: str = "",
        now: Optional[float] = None,
    ) -> RateLimitResult:
        ts = now or time.time()
        config = self._get_config(tier)
        key = self._make_key(identity, tier, service)
        count = await self._store.add_and_count(key, ts, config.window_seconds)
        remaining = max(0, config.requests - count)
        reset_at = ts + config.window_seconds
        if count <= config.requests:
            return RateLimitResult(
                allowed=True, remaining=remaining, reset_at=reset_at, limit=config.requests
            )
        oldest = await self._store.get_oldest(key, ts, config.window_seconds)
        retry_after = (oldest + config.window_seconds - ts) if oldest else config.window_seconds
        if self._abuse_hook and count == config.requests + 1:
            try:
                await self._abuse_hook(identity, tier, count)
            except Exception:
                pass
        return RateLimitResult(
            allowed=False, remaining=0, reset_at=reset_at,
            limit=config.requests, retry_after=round(retry_after, 2),
        )

    def gateway_middleware(self, service: str = ""):
        limiter = self
        async def middleware(identity: str, tier: Tier) -> RateLimitResult:
            return await limiter.check(identity, tier, service)
        return middleware