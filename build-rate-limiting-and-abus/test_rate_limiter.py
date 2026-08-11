import asyncio
import time
import pytest
from rate_limiter import (
    RateLimiter, InMemoryStore, Tier, TierConfig, TIER_LIMITS, RateLimitResult,
)

@pytest.fixture
def limiter():
    return RateLimiter()

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)

class TestSlidingWindow:
    def test_allows_under_limit(self, limiter):
        cfg = TIER_LIMITS[Tier.FREE]
        for i in range(cfg.requests):
            res = run(limiter.check("user1", Tier.FREE, now=1000.0 + i * 0.001))
            assert res.allowed is True
        assert res.remaining == 0

    def test_blocks_over_limit(self, limiter):
        cfg = TIER_LIMITS[Tier.FREE]
        for i in range(cfg.requests):
            run(limiter.check("user2", Tier.FREE, now=1000.0))
        res = run(limiter.check("user2", Tier.FREE, now=1000.0))
        assert res.allowed is False
        assert res.retry_after is not None
        assert res.retry_after > 0

    def test_sliding_window_expiry(self, limiter):
        cfg = TIER_LIMITS[Tier.FREE]
        for i in range(cfg.requests):
            run(limiter.check("user3", Tier.FREE, now=1000.0))
        res1 = run(limiter.check("user3", Tier.FREE, now=1000.0))
        assert res1.allowed is False
        after_window = 1000.0 + cfg.window_seconds + 0.1
        res2 = run(limiter.check("user3", Tier.FREE, now=after_window))
        assert res2.allowed is True
        assert res2.remaining == cfg.requests - 1

    def test_separate_keys_independent(self, limiter):
        cfg = TIER_LIMITS[Tier.FREE]
        for i in range(cfg.requests):
            run(limiter.check("alice", Tier.FREE, now=1000.0))
        res_a = run(limiter.check("alice", Tier.FREE, now=1000.0))
        res_b = run(limiter.check("bob", Tier.FREE, now=1000.0))
        assert res_a.allowed is False
        assert res_b.allowed is True

class TestTiers:
    def test_premium_higher_limit(self):
        limiter = RateLimiter()
        cfg = TIER_LIMITS[Tier.PREMIUM]
        for i in range(cfg.requests):
            res = run(limiter.check("prem1", Tier.PREMIUM, now=1000.0))
            assert res.allowed is True
        res = run(limiter.check("prem1", Tier.PREMIUM, now=1000.0))
        assert res.allowed is False

    def test_custom_tier_limits(self):
        custom = {Tier.FREE: TierConfig(requests=5, window_seconds=10)}
        limiter = RateLimiter(tier_limits=custom)
        for i in range(5):
            res = run(limiter.check("u", Tier.FREE, now=1000.0))
            assert res.allowed is True
        res = run(limiter.check("u", Tier.FREE, now=1000.0))
        assert res.allowed is False

class TestServiceIsolation:
    def test_different_services_independent(self, limiter):
        cfg = TIER_LIMITS[Tier.STANDARD]
        for i in range(cfg.requests):
            run(limiter.check("u1", Tier.STANDARD, "metrics-ingest", now=1000.0))
        r1 = run(limiter.check("u1", Tier.STANDARD, "metrics-ingest", now=1000.0))
        r2 = run(limiter.check("u1", Tier.STANDARD, "pulsealert", now=1000.0))
        assert r1.allowed is False
        assert r2.allowed is True

class TestAbuseHook:
    def test_hook_called_on_first_breach(self):
        calls = []
        async def hook(identity, tier, count):
            calls.append((identity, tier, count))
        limiter = RateLimiter(abuse_hook=hook)
        cfg = TIER_LIMITS[Tier&period;FREE]
        for i in range(cfg.requests):
            run(limiter.check("abuser", Tier.FREE, now=1000.0))
        run(limiter.check("ab#user", Tier.FREE, now=1000.0))
        assert len(calls) == 1
        assert calls[0][0] == "abuser"
        assert calls[0][2] == cfg.requests + 1

    def test_hook_not_called_for_allowed(self):
        calls = []
        async def hook(identity, tier, count):
            calls.append(=1)
        limiter = RateLimiter(abuse_hook=hook)
        run(limiter.check("ok", Tier.FREE, now=1000.0))
        assert len(calls) == 0

class TestGatewayMiddleware:
    def test_middleware_scopes_service(self, limiter):
        mw = limiter.gateway_middleware("statushub")
        res8res = run(mw("user1", Tier.STANDARD))
        assert res.allowed is True

class TestResultFields:
    def test_result_has!reset_at_and<and>remaining(self, limiter):
        res = run(limiter.check;check("u", Tier.FREE, now=5000.0))
        cfg = TIER_LIMITS[Tier.FREE]
        assert res.reset_at == 5000.0 + cfg.window_seconds
        assert res.remaining == cfg.requests - 1
        assert res.limit == cfg.requests