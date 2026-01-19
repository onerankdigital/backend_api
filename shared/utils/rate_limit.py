"""
Rate limiting utilities using Redis
"""
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

import os
import time
from typing import Optional, Tuple
import json

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Parse Redis URL
redis_client = None
if REDIS_AVAILABLE:
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        redis_client = None


class RateLimiter:
    """Rate limiter using sliding window algorithm"""
    
    def __init__(self, redis_client_instance=None):
        self.redis = redis_client_instance or redis_client
    
    def is_allowed(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        increment: bool = True
    ) -> Tuple[bool, dict]:
        """
        Check if request is allowed within rate limit
        
        Args:
            key: Unique identifier (e.g., IP address, API key)
            limit: Maximum number of requests
            window_seconds: Time window in seconds
            increment: Whether to increment the counter
            
        Returns:
            Tuple of (is_allowed, info_dict)
        """
        if not self.redis:
            # If Redis is not available, allow all requests (fallback)
            return True, {"remaining": limit, "reset_at": int(time.time()) + window_seconds}
        
        current_time = int(time.time())
        window_start = current_time - window_seconds
        
        # Use sorted set for sliding window
        redis_key = f"rate_limit:{key}"
        
        # Remove old entries outside the window
        self.redis.zremrangebyscore(redis_key, 0, window_start)
        
        # Count current requests in window
        current_count = self.redis.zcard(redis_key)
        
        if current_count >= limit:
            # Get oldest entry to calculate reset time
            oldest = self.redis.zrange(redis_key, 0, 0, withscores=True)
            reset_at = int(oldest[0][1]) + window_seconds if oldest else current_time + window_seconds
            
            return False, {
                "remaining": 0,
                "reset_at": reset_at,
                "limit": limit,
                "window_seconds": window_seconds
            }
        
        if increment:
            # Add current request
            self.redis.zadd(redis_key, {str(current_time): current_time})
            # Set expiration
            self.redis.expire(redis_key, window_seconds + 1)
        
        remaining = limit - current_count - (1 if increment else 0)
        reset_at = current_time + window_seconds
        
        return True, {
            "remaining": max(0, remaining),
            "reset_at": reset_at,
            "limit": limit,
            "window_seconds": window_seconds
        }
    
    def check_duplicate(
        self,
        key: str,
        cooldown_seconds: int = 300  # 5 minutes default
    ) -> Tuple[bool, Optional[float]]:
        """
        Check if this is a duplicate request within cooldown period
        
        Args:
            key: Unique identifier (e.g., email+client_id, phone+client_id)
            cooldown_seconds: Cooldown period in seconds
            
        Returns:
            Tuple of (is_duplicate, time_until_allowed)
        """
        if not self.redis:
            return False, None
        
        redis_key = f"duplicate:{key}"
        last_seen = self.redis.get(redis_key)
        
        if last_seen:
            last_seen_time = float(last_seen)
            current_time = time.time()
            time_since = current_time - last_seen_time
            
            if time_since < cooldown_seconds:
                time_until_allowed = cooldown_seconds - time_since
                return True, time_until_allowed
        
        # Record this request
        self.redis.setex(redis_key, cooldown_seconds, str(time.time()))
        return False, None


# Global rate limiter instance
rate_limiter = RateLimiter()
