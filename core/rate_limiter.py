import asyncio
import time
from typing import Dict, Optional
import logging

class RateLimiter:
    def __init__(self, rate_limit: int = 10, window: float = 1.0):
        self.rate_limit = rate_limit
        self.window = window
        self.tokens = rate_limit
        self.last_update = time.time()
        self._lock = asyncio.Lock()
        self.logger = logging.getLogger('RateLimiter')
        self._scan_limits: Dict[str, dict] = {}

    async def acquire(self, scan_id: str) -> bool:
        """Acquire a token for rate limiting"""
        async with self._lock:
            await self._replenish_tokens()
            
            if scan_id not in self._scan_limits:
                self._scan_limits[scan_id] = {
                    'tokens': self.rate_limit,
                    'last_update': time.time()
                }

            if self._scan_limits[scan_id]['tokens'] >= 1:
                self._scan_limits[scan_id]['tokens'] -= 1
                return True
                
            self.logger.warning(f"Rate limit reached for scan {scan_id}")
            return False

    async def _replenish_tokens(self):
        """Replenish tokens based on time passed"""
        now = time.time()
        for scan_id, limit_data in self._scan_limits.items():
            time_passed = now - limit_data['last_update']
            tokens_to_add = time_passed * (self.rate_limit / self.window)
            limit_data['tokens'] = min(self.rate_limit, limit_data['tokens'] + tokens_to_add)
            limit_data['last_update'] = now

    async def cleanup(self, scan_id: str):
        """Cleanup rate limit data for a scan"""
        async with self._lock:
            if scan_id in self._scan_limits:
                del self._scan_limits[scan_id] 