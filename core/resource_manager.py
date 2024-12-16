import psutil
import asyncio
import logging
from typing import Dict, Optional

class ResourceManager:
    def __init__(self):
        self.max_memory = 1024 * 1024 * 1024  # 1GB
        self.max_connections = 100
        self.active_connections = 0
        self.resources: Dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self.logger = logging.getLogger('ResourceManager')

    async def allocate(self, scan_id: str):
        """Allocate resources for a scan"""
        async with self._lock:
            if not await self.check_resources():
                raise ResourceWarning("System resources are exhausted")
                
            self.resources[scan_id] = {
                'start_time': time.time(),
                'memory_start': psutil.Process().memory_info().rss,
                'connections': 0
            }

    async def check_resources(self) -> bool:
        """Check if system has available resources"""
        try:
            memory_usage = psutil.Process().memory_info().rss
            if memory_usage > self.max_memory:
                self.logger.warning("Memory usage exceeded limit")
                return False

            if self.active_connections >= self.max_connections:
                self.logger.warning("Connection limit reached")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error checking resources: {str(e)}")
            return False

    async def cleanup(self, scan_id: str):
        """Cleanup resources for a scan"""
        async with self._lock:
            if scan_id in self.resources:
                try:
                    # Calculate resource usage
                    end_memory = psutil.Process().memory_info().rss
                    memory_used = end_memory - self.resources[scan_id]['memory_start']
                    duration = time.time() - self.resources[scan_id]['start_time']
                    
                    self.logger.info(
                        f"Scan {scan_id} used {memory_used/1024/1024:.2f}MB "
                        f"over {duration:.2f} seconds"
                    )
                    
                    del self.resources[scan_id]
                    
                except Exception as e:
                    self.logger.error(f"Error cleaning up resources: {str(e)}")

    async def monitor(self):
        """Monitor resource usage periodically"""
        while True:
            try:
                if not await self.check_resources():
                    await self.cleanup_oldest()
                await asyncio.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"Error in resource monitor: {str(e)}")

    async def cleanup_oldest(self):
        """Cleanup the oldest scan if resources are low"""
        if not self.resources:
            return

        oldest_scan_id = min(
            self.resources.keys(),
            key=lambda k: self.resources[k]['start_time']
        )
        await self.cleanup(oldest_scan_id) 