from abc import ABC, abstractmethod
from colorama import Fore, Style
from datetime import datetime
import traceback
import aiohttp
import asyncio
import logging
import sys
import os
import urllib.parse

# Try to import psutil but make it optional
try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    PSUTIL = None
    HAVE_PSUTIL = False
    print("[INFO] psutil not installed. Resource monitoring will be limited. Install with: pip install psutil")

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s',
    handlers=[
        logging.FileHandler('scanner_debug.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class BaseScanner(ABC):
    def __init__(self, session, config):
        self.session = session
        self.config = config or {}
        self.vulnerabilities = []
        self.scan_logs = []
        self.logger = logging.getLogger(self.__class__.__name__)
        self.url = None  # Add this to store the current URL
        self.log_colors = {
            'INFO': 'blue',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'SUCCESS': 'green',
            'DEBUG': 'gray'
        }

    def log(self, message, level='INFO', details=None):
        """Enhanced logging with better error context"""
        try:
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': level,
                'message': message,
                'details': details,
                'scanner': self.__class__.__name__,
                'url': self.url  # Include current URL in logs
            }
            self.scan_logs.append(log_entry)
            
            # Format message with context
            context_msg = f"[{self.__class__.__name__}] "
            if self.url:
                context_msg += f"[{self.url}] "
            context_msg += message

            # Log to logger
            log_level = getattr(logging, level.upper(), logging.INFO)
            self.logger.log(log_level, context_msg)

        except Exception as e:
            # Fallback logging if something goes wrong
            self.logger.error(f"Logging error: {str(e)}")
            self.logger.error(f"Original message: {message}")

    async def make_request(self, url, method='GET', data=None, headers=None):
        """Make HTTP request with better error handling and session management"""
        if not self.session:
            self.logger.error("No session available")
            return None, None

        # Retry logic for failed requests
        max_retries = self.config.get('max_retries', 3)
        retry_delay = self.config.get('retry_delay', 1)
        timeout = self.config.get('timeout', 30)

        for attempt in range(max_retries):
            try:
                # Ensure session is active
                if self.session.closed:
                    self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout))
                    self.logger.info("Created new session due to closed session")

                # Merge headers with defaults
                request_headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': '*/*',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive'
                }
                if self.config and 'headers' in self.config:
                    request_headers.update(self.config['headers'])
                if headers:
                    request_headers.update(headers)

                async with self.session.request(
                    method,
                    url,
                    data=data,
                    headers=request_headers,
                    ssl=False,
                    timeout=timeout
                ) as response:
                    content = await response.text()
                    return response, content

            except asyncio.TimeoutError:
                self.logger.warning(f"Request timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                continue
            except aiohttp.ClientError as e:
                self.logger.error(f"Request error: {str(e)} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                continue
            except Exception as e:
                self.logger.error(f"Unexpected error: {str(e)}")
                return None, None

        self.logger.error(f"All {max_retries} request attempts failed")
        return None, None

    async def ensure_session(self):
        """Ensure session is available and active"""
        if not self.session or self.session.closed:
            self.logger.warning("Session unavailable or closed, creating new session")
            try:
                connector = aiohttp.TCPConnector(
                    limit=self.config.get('max_concurrent_requests', 10),
                    ttl_dns_cache=300,
                    use_dns_cache=True,
                    force_close=True,
                    enable_cleanup_closed=True,
                    ssl=False
                )
                
                self.session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(
                        total=self.config.get('request_timeout', 30),
                        connect=10,
                        sock_connect=10,
                        sock_read=10
                    ),
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': '*/*',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Connection': 'keep-alive'
                    }
                )
                return True
            except Exception as e:
                self.logger.error(f"Failed to create new session: {str(e)}")
                return False
        return True

    async def cleanup(self):
        """Cleanup resources"""
        if hasattr(self, 'session') and self.session and not self.session.closed:
            try:
                await self.session.close()
            except Exception as e:
                self.logger.error(f"Error closing session: {str(e)}")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()
        if exc_val:
            print(f"[DEBUG] Error in context manager: {str(exc_val)}")
            print(f"[DEBUG] Traceback: {traceback.format_exc()}")

    @abstractmethod
    async def scan(self, url):
        """Implement in subclasses"""
        pass

    def add_vulnerability(self, vulnerability_type, description, severity="Medium", evidence=None, reproduction_steps=None):
        """Add a vulnerability finding with enhanced details"""
        try:
            vulnerability = {
                'type': vulnerability_type,
                'description': description,
                'severity': severity,
                'evidence': evidence or {},
                'reproduction_steps': reproduction_steps or [],
                'timestamp': datetime.now().isoformat(),
                'url': self.url,
                'scanner': self.__class__.__name__
            }
            
            self.vulnerabilities.append(vulnerability)
            self.log(
                f"Found {severity} severity {vulnerability_type} vulnerability",
                level='WARNING',
                details=vulnerability
            )
            
        except Exception as e:
            self.log(f"Error adding vulnerability: {str(e)}", level='ERROR')

    async def log_progress(self, message, color=Fore.YELLOW):
        """Log progress message"""
        print(f"{color}[*] {message}{Style.RESET_ALL}")

    async def log_error(self, message):
        """Log error message"""
        print(f"{Fore.RED}[!] {message}{Style.RESET_ALL}")

    async def log_success(self, message):
        """Log success message"""
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

    def get_debug_info(self):
        """Get debug information"""
        return {
            'debug_info': self.debug_info,
            'scan_duration': (self.debug_info['scan_end_time'] - self.debug_info['scan_start_time']).total_seconds() if self.debug_info['scan_end_time'] else None,
            'success_rate': ((self.debug_info['requests_made'] - self.debug_info['requests_failed']) / self.debug_info['requests_made'] * 100) if self.debug_info['requests_made'] > 0 else 0,
            'error_summary': {error['type']: len([e for e in self.debug_info['errors'] if e['type'] == error['type']]) for error in self.debug_info['errors']}
        }