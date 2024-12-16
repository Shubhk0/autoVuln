import time
from typing import Dict, Optional, Any
import logging
import json
from datetime import datetime

class ResultCache:
    def __init__(self, ttl: int = 3600):
        self.ttl = ttl  # Cache TTL in seconds
        self._cache: Dict[str, dict] = {}
        self.logger = logging.getLogger('ResultCache')
        self._max_entries = 1000
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # 5 minutes

    async def get(self, key: str) -> Optional[Any]:
        """Get cached result if not expired"""
        await self._cleanup_expired()
        
        if key in self._cache:
            entry = self._cache[key]
            if time.time() - entry['timestamp'] < self.ttl:
                self.logger.debug(f"Cache hit for {key}")
                return entry['data']
            else:
                del self._cache[key]
                self.logger.debug(f"Cache expired for {key}")
        return None

    async def set(self, key: str, data: Any):
        """Cache result with timestamp"""
        await self._cleanup_expired()
        
        if len(self._cache) >= self._max_entries:
            await self._cleanup_oldest()

        self._cache[key] = {
            'data': data,
            'timestamp': time.time()
        }
        self.logger.debug(f"Cached result for {key}")

    async def _cleanup_expired(self):
        """Remove expired entries"""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        expired_keys = [
            k for k, v in self._cache.items()
            if now - v['timestamp'] > self.ttl
        ]
        for key in expired_keys:
            del self._cache[key]

        self._last_cleanup = now
        if expired_keys:
            self.logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")

    async def _cleanup_oldest(self):
        """Remove oldest entries when cache is full"""
        if not self._cache:
            return

        # Remove 10% of oldest entries
        num_to_remove = max(1, len(self._cache) // 10)
        sorted_keys = sorted(
            self._cache.keys(),
            key=lambda k: self._cache[k]['timestamp']
        )
        
        for key in sorted_keys[:num_to_remove]:
            del self._cache[key]

        self.logger.info(f"Removed {num_to_remove} oldest cache entries")

    def get_stats(self) -> dict:
        """Get cache statistics"""
        now = time.time()
        return {
            'total_entries': len(self._cache),
            'expired_entries': sum(1 for v in self._cache.values() if now - v['timestamp'] > self.ttl),
            'cache_size_mb': sum(len(str(v['data'])) for v in self._cache.values()) / 1024 / 1024,
            'oldest_entry_age': max((now - v['timestamp'] for v in self._cache.values()), default=0)
        } 