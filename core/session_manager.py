import asyncio
import aiohttp
import time
from typing import Dict, Optional
import logging

class SessionManager:
    def __init__(self):
        self._session_pool: Dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self._max_sessions = 10
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = time.time()
        self.logger = logging.getLogger('SessionManager')

    async def get_session(self, scan_id: str) -> aiohttp.ClientSession:
        """Get or create a session for a scan"""
        async with self._lock:
            await self._cleanup_old_sessions()
            
            if scan_id not in self._session_pool:
                if len(self._session_pool) >= self._max_sessions:
                    await self._cleanup_oldest_session()
                
                session = await self._create_session()
                self._session_pool[scan_id] = {
                    'session': session,
                    'last_used': time.time(),
                    'active': True
                }
                self.logger.debug(f"Created new session for scan {scan_id}")
            else:
                self._session_pool[scan_id]['last_used'] = time.time()
                
            return self._session_pool[scan_id]['session']

    async def _create_session(self) -> aiohttp.ClientSession:
        """Create a new session with optimized settings"""
        connector = aiohttp.TCPConnector(
            limit=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
            force_close=True,
            enable_cleanup_closed=True
        )
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
            }
        )

    async def _cleanup_old_sessions(self):
        """Cleanup sessions older than cleanup_interval"""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        for scan_id, session_data in list(self._session_pool.items()):
            if now - session_data['last_used'] > self._cleanup_interval:
                await self.close_session(scan_id)

        self._last_cleanup = now

    async def _cleanup_oldest_session(self):
        """Cleanup the oldest session when pool is full"""
        if not self._session_pool:
            return

        oldest_scan_id = min(
            self._session_pool.keys(),
            key=lambda k: self._session_pool[k]['last_used']
        )
        await self.close_session(oldest_scan_id)

    async def close_session(self, scan_id: str):
        """Close and cleanup a specific session"""
        if scan_id in self._session_pool:
            session_data = self._session_pool[scan_id]
            try:
                if not session_data['session'].closed:
                    await session_data['session'].close()
                del self._session_pool[scan_id]
                self.logger.debug(f"Closed session for scan {scan_id}")
            except Exception as e:
                self.logger.error(f"Error closing session {scan_id}: {str(e)}")

    async def cleanup(self):
        """Cleanup all sessions"""
        async with self._lock:
            for scan_id in list(self._session_pool.keys()):
                await self.close_session(scan_id) 