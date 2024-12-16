"""
VulnerabilityScanner - An asynchronous web application security scanner

This module provides a comprehensive vulnerability scanning solution with support for:
- XSS (Cross-Site Scripting)
- SQL Injection
- CSRF (Cross-Site Request Forgery)
- Security Headers
- SSL/TLS Configuration

Usage:
    scanner = VulnerabilityScanner(url="https://example.com")
    async with scanner:
        results = await scanner.scan()
"""

from typing import Dict, List, Optional, Set, Any, Tuple
from modules.xss_scanner import XSSScanner
from modules.sql_scanner import SQLScanner
from modules.csrf_scanner import CSRFScanner
from modules.header_scanner import HeaderScanner
from modules.ssl_scanner import SSLScanner
import aiohttp
import asyncio
from datetime import datetime
import logging
from colorama import Fore, Style, init
import sys
import traceback
import urllib.parse
import json
from bs4 import BeautifulSoup
import uuid
from core.logging_manager import LoggingManager
import time
import os
import psutil
import threading
import random

# Initialize colorama for cross-platform color support
init()

# Set up logging with file output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SessionManager:
    """
    Manages HTTP session pooling and lifecycle
    
    Attributes:
        _max_pool_size: Maximum number of concurrent sessions
        _connection_timeout: Timeout for session acquisition
    """
    def __init__(self):
        self._session = None
        self._connector = None
        self._lock = asyncio.Lock()
        self._active = False
        self._ref_count = 0
        self.logger = logging.getLogger('SessionManager')
        self._initialized = False
        self._max_connections = 20  # Add connection pool limit
        self._connection_timeout = 30  # Add timeout
        self._connection_queue = asyncio.Queue()  # Add connection queue
        self._session_pool = []
        self._max_pool_size = 20

    async def ensure_initialized(self):
        """Ensure session is properly initialized with connection pooling"""
        if not self._initialized:
            try:
                # Initialize connection pool
                for _ in range(self._max_pool_size):
                    connector = aiohttp.TCPConnector(
                        limit=10,
                        ttl_dns_cache=300,
                        use_dns_cache=True,
                        force_close=True,
                        enable_cleanup_closed=True,
                        ssl=False
                    )
                    
                    session = aiohttp.ClientSession(
                        connector=connector,
                        timeout=aiohttp.ClientTimeout(total=30),
                        headers=self.config['headers']
                    )
                    self._session_pool.append(session)
                    await self._connection_queue.put(session)
                
                self._initialized = True
                return True
            except Exception as e:
                self.logger.error(f"Session initialization error: {str(e)}")
                return False
        return True

    async def get_session(self):
        """Get session from pool with improved error handling"""
        async with self._lock:
            try:
                if not await self.ensure_initialized():
                    return None
                
                # Try to get session from pool with timeout
                try:
                    session = await asyncio.wait_for(
                        self._connection_queue.get(),
                        timeout=self._connection_timeout
                    )
                    
                    # Verify session is still valid
                    if session.closed:
                        # Create new session if closed
                        session = await self._create_new_session()
                        
                    return session
                    
                except asyncio.TimeoutError:
                    self.logger.warning("Session pool exhausted, creating new session")
                    return await self._create_new_session()
                    
            except Exception as e:
                self.logger.error(f"Error getting session: {str(e)}")
                return None

    async def release(self):
        """Return session to pool"""
        async with self._lock:
            try:
                if self._session and not self._session.closed:
                    await self._connection_queue.put(self._session)
            except Exception as e:
                self.logger.error(f"Error releasing session: {str(e)}")

    async def cleanup(self):
        """Cleanup session and connector"""
        async with self._lock:
            try:
                if self._session and not self._session.closed:
                    await self._session.close()
                if self._connector and not self._connector.closed:
                    await self._connector.close()
            except Exception as e:
                logging.error(f"Error during cleanup: {str(e)}")
            finally:
                self._session = None
                self._connector = None
                self._active = False
                self._ref_count = 0

class RateLimiter:
    def __init__(self, requests_per_second, burst_size):
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
        self._waiting = 0

    async def acquire(self):
        """Improved rate limiting with queue tracking"""
        async with self._lock:
            now = time.monotonic()
            time_passed = now - self.last_update
            self.tokens = min(
                self.burst_size,
                self.tokens + time_passed * self.requests_per_second
            )
            
            self._waiting += 1
            try:
                if self.tokens < 1:
                    wait_time = (1 - self.tokens) / self.requests_per_second
                    # Add jitter to prevent thundering herd
                    wait_time += random.uniform(0, 0.1)
                    await asyncio.sleep(wait_time)
                    self.tokens = 1
                
                self.tokens -= 1
                self.last_update = now
            finally:
                self._waiting -= 1

class VulnerabilityScanner:
    def __init__(self, url):
        try:
            # Initialize logging
            self.log_manager = LoggingManager()
            self.logger = self.log_manager.get_logger('scanner')
            
            # Initialize log colors
            self.log_colors = {
                'INFO': 'blue',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'SUCCESS': 'green',
                'DEBUG': 'gray'
            }
            
            self.logger.info(f"Initializing scanner for {url}")
            
            # Validate URL
            self.url = self.validate_and_clean_url(url)
            
            # Initialize components
            self.session_manager = SessionManager()
            self.scanners = {}
            self.seen_urls = set()
            self.scan_logs = []
            self._initialized = False
            self._scan_id = str(uuid.uuid4())
            self._stop_event = asyncio.Event()
            
            # Initialize configuration
            self.init_config()
            
            self.rate_limiter = RateLimiter(
                requests_per_second=10,
                burst_size=20
            )
            
            self.metrics = {
                'requests_made': 0,
                'requests_failed': 0,
                'vulnerabilities_found': 0,
                'scan_duration': 0,
                'errors': [],
                'performance_metrics': {}
            }
            
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Scanner initialization error: {str(e)}", exc_info=True)
            else:
                print(f"Scanner initialization error: {str(e)}")
            raise

    def init_config(self):
        """Optimized scanner configuration"""
        self.config = {
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive'
            },
            'timeout': 15,  # Reduced from 30
            'max_redirects': 3,  # Reduced from 5
            'verify_ssl': False,
            'max_retries': 2,  # Reduced from 3
            'retry_delay': 0.5,  # Reduced from 1
            'concurrent_scans': 10,  # Increased from 5
            'max_depth': 2,  # Reduced from 3
            'max_urls_per_scan': 50,  # Reduced from 100
            'scan_timeout': 180,  # Reduced from 300
            'max_concurrent_requests': 20,  # Increased from 10
            'request_timeout': 15,  # Reduced from 30
            'connect_timeout': 5,  # Reduced from 10
            'chunk_size': 10,  # Increased from 5
            'crawl_scope': 'domain',
            'exclude_paths': ['/logout', '/signout', '/delete', '/static', '/assets', '/images'],
            'exclude_extensions': ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg']
        }

    def validate_and_clean_url(self, url):
        """Validate and clean URL"""
        try:
            # Remove whitespace and convert to lowercase
            url = url.strip().lower()
            
            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            # Parse and validate URL
            parsed = urllib.parse.urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError("Invalid URL format")
                
            # Reconstruct URL
            return urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path or '/',
                parsed.params,
                parsed.query,
                ''  # Remove fragment
            ))
            
        except Exception as e:
            raise ValueError(f"URL validation error: {str(e)}")

    async def initialize(self):
        """Initialize scanner with error handling and recovery"""
        if self._initialized:
            return True

        max_retries = 3
        for attempt in range(max_retries):
            try:
                session = await self.get_session_with_retry()
                if not session:
                    raise Exception("Failed to create session")

                self.scanners = await self.initialize_scanners(session)
                self._initialized = True
                self.logger.info("Scanner initialized successfully")
                return True
                
            except Exception as e:
                self.logger.error(f"Initialization attempt {attempt + 1} failed: {str(e)}")
                await asyncio.sleep(1)  # Add backoff delay
                await self.cleanup()
                
        return False

    async def get_session_with_retry(self):
        """Get session with retry logic"""
        for attempt in range(3):
            try:
                session = await self.session_manager.get_session()
                if session:
                    return session
                if attempt < 2:
                    await asyncio.sleep(1)
            except Exception as e:
                self.logger.error(f"Session creation attempt {attempt + 1} failed: {str(e)}")
        return None

    async def initialize_scanners(self, session):
        """Initialize scanner modules"""
        scanner_config = {
            'max_concurrent_requests': 10,
            'request_timeout': 30,
            'max_retries': 3,
            'retry_delay': 1,
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive'
            },
            'scan_id': self._scan_id
        }
        
        return {
            'xss': XSSScanner(session, scanner_config),
            'sql': SQLScanner(session, scanner_config),
            'csrf': CSRFScanner(session, scanner_config),
            'headers': HeaderScanner(session, scanner_config),
            'ssl': SSLScanner(session, scanner_config)
        }

    async def scan(self, checks=None):
        """Optimized scan with concurrent execution"""
        start_time = datetime.now()
        try:
            # Initialize scanner
            if not await self.initialize():
                raise Exception("Scanner initialization failed")

            self.log("Starting security scan", "INFO")
            results = []
            scan_logs = []
            
            # Phase 1: Fast crawl with concurrency
            try:
                self.log("Phase 1: Crawling target", "INFO")
                crawl_task = asyncio.create_task(self.crawl_site())
                await asyncio.wait_for(crawl_task, timeout=60)  # 1 minute timeout for crawling
                self.log(f"Found {len(self.seen_urls)} URLs", "INFO")
            except Exception as e:
                self.log(f"Crawling error: {str(e)}", "ERROR")
                self.seen_urls = {self.url}

            # Phase 2: Run scanners in specific order
            if checks:
                self.log("Phase 2: Running security checks", "INFO")
                scanner_tasks = []

                # Always run XSS scanner first
                if checks.get('xss', False):
                    scanner_tasks.append(self.run_scanner_with_timeout('xss'))

                # Then run SQL scanner
                if checks.get('sql', False):
                    scanner_tasks.append(self.run_scanner_with_timeout('sql'))

                # Run all scanners concurrently
                scanner_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)
                
                # Process results
                for result in scanner_results:
                    if isinstance(result, Exception):
                        self.log(f"Scanner error: {str(result)}", "ERROR")
                        continue
                    if result:
                        if result.get('vulnerabilities'):
                            results.extend(result['vulnerabilities'])
                        if result.get('logs'):
                            scan_logs.extend(result['logs'])

            # Process results efficiently
            unique_results = self.deduplicate_vulnerabilities(results)
            prioritized_results = self.prioritize_vulnerabilities(unique_results)
            
            scan_duration = (datetime.now() - start_time).total_seconds()
            
            return {
                'scan_id': self._scan_id,
                'url': self.url,
                'vulnerabilities': prioritized_results,
                'logs': scan_logs,
                'stats': {
                    'total_urls': len(self.seen_urls),
                    'total_vulnerabilities': len(results),
                    'unique_vulnerabilities': len(unique_results),
                    'severity_counts': self.count_severities(prioritized_results),
                    'scan_duration': scan_duration
                },
                'status': 'completed'
            }

        except Exception as e:
            self.log(f"Scan error: {str(e)}", "ERROR")
            return {
                'scan_id': self._scan_id,
                'url': self.url,
                'error': str(e),
                'logs': scan_logs,
                'stats': {
                    'scan_duration': (datetime.now() - start_time).total_seconds()
                },
                'status': 'error'
            }
        finally:
            await self.cleanup()

    async def run_nuclei_scan(self):
        """Run Nuclei scan after standard checks"""
        try:
            self.log("Starting Nuclei scan", "INFO")
            
            # Create Nuclei scanner with current session
            nuclei_scanner = NucleiScanner(self.session, {
                **self.config,
                'scan_id': self._scan_id,
                'templates': [
                    'cves',
                    'vulnerabilities',
                    'exposures',
                    'misconfiguration'
                ]
            })

            # Run Nuclei scan
            result = await nuclei_scanner.scan(self.url)
            
            if result and result.get('vulnerabilities'):
                self.log(f"Nuclei found {len(result['vulnerabilities'])} vulnerabilities", "INFO")
            else:
                self.log("Nuclei scan completed with no findings", "INFO")
                
            return result

        except Exception as e:
            self.log(f"Error in Nuclei scan: {str(e)}", "ERROR")
            return None

    async def run_scanner_with_timeout(self, check_type):
        """Run scanner with timeout"""
        try:
            return await asyncio.wait_for(
                self.run_scanner(check_type),
                timeout=self.config['scan_timeout']
            )
        except asyncio.TimeoutError:
            self.log(f"{check_type} scanner timed out", "WARNING")
            return []

    def deduplicate_vulnerabilities(self, vulnerabilities):
        """Remove duplicate vulnerabilities"""
        unique_vulns = []
        seen = set()
        
        for vuln in vulnerabilities:
            # Create a unique key based on relevant fields
            key = f"{vuln['type']}:{vuln['description']}:{vuln.get('url', '')}"
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
                
        return unique_vulns

    def prioritize_vulnerabilities(self, vulnerabilities):
        """Prioritize vulnerabilities based on severity"""
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        return sorted(
            vulnerabilities,
            key=lambda x: severity_order.get(x['severity'], 999)
        )

    async def crawl_site(self):
        """Optimized concurrent crawling"""
        try:
            self.log("Starting site crawl", "INFO")
            urls_to_scan = {self.url}
            self.seen_urls = set()
            
            async def process_url(url):
                if url in self.seen_urls:
                    return set()
                
                try:
                    response, content = await self.make_request(url)
                    if not response or not content:
                        return set()
                    
                    new_urls = set()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urllib.parse.urljoin(url, href)
                        
                        if (self.is_url_in_scope(full_url) and 
                            full_url not in self.seen_urls and 
                            len(self.seen_urls) < self.config['max_urls_per_scan']):
                            new_urls.add(full_url)
                    
                    self.seen_urls.add(url)
                    return new_urls
                    
                except Exception as e:
                    self.log(f"Error crawling URL {url}: {str(e)}", "ERROR")
                    return set()

            while urls_to_scan and len(self.seen_urls) < self.config['max_urls_per_scan']:
                # Process URLs in batches
                batch = list(urls_to_scan)[:self.config['chunk_size']]
                urls_to_scan = urls_to_scan - set(batch)
                
                # Process batch concurrently
                tasks = [process_url(url) for url in batch]
                results = await asyncio.gather(*tasks)
                
                # Add new URLs to scan queue
                for new_urls in results:
                    urls_to_scan.update(new_urls)
                
            self.log(f"Completed crawl, found {len(self.seen_urls)} URLs", "INFO")
            
        except Exception as e:
            self.log(f"Error during crawl: {str(e)}", "ERROR")
        finally:
            # No need to call release() here as it's handled by make_request()
            pass

    def is_url_in_scope(self, url):
        """Check if URL is in scan scope"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            parsed_base = urllib.parse.urlparse(self.url)
            
            # Check domain scope
            if self.config['crawl_scope'] == 'domain':
                if parsed_url.netloc != parsed_base.netloc:
                    return False
            
            # Check file extensions
            path = parsed_url.path.lower()
            if any(path.endswith(ext) for ext in self.config['exclude_extensions']):
                return False
                
            # Check excluded paths
            if any(excluded in path for excluded in self.config['exclude_paths']):
                return False
                
            return True
            
        except Exception:
            return False

    async def run_scanner(self, check_type):
        """Run scanner and collect logs"""
        try:
            scanner = self.scanners[check_type]
            result = await scanner.scan(self.url)
            
            # Collect scanner logs
            if hasattr(scanner, 'scan_logs'):
                self.scan_logs.extend(scanner.scan_logs)
            
            return result
            
        except Exception as e:
            self.log(f"Error in {check_type} scanner: {str(e)}", 'ERROR')
            raise
        finally:
            await self.session_manager.release()

    async def batch_request(self, urls):
        """Make concurrent requests in batches"""
        results = []
        for i in range(0, len(urls), self.config['chunk_size']):
            chunk = urls[i:i + self.config['chunk_size']]
            tasks = [self.make_request(url) for url in chunk]
            chunk_results = await asyncio.gather(*tasks, return_exceptions=True)
            results.extend(chunk_results)
        return results

    async def make_request(self, url, method='GET', data=None, headers=None):
        """Make request with improved error handling and retries"""
        for attempt in range(self.config['max_retries']):
            try:
                # Wait for rate limiter
                await self.rate_limiter.acquire()
                
                session = await self.session_manager.get_session()
                if not session:
                    self.logger.error("Failed to get session")
                    await asyncio.sleep(self.config['retry_delay'])
                    continue

                # Update metrics
                self.metrics['requests_made'] += 1

                async with session.request(
                    method, 
                    url, 
                    data=data, 
                    headers=headers,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(
                        total=self.config['request_timeout'],
                        connect=self.config['connect_timeout']
                    ),
                    allow_redirects=True,
                    max_redirects=self.config['max_redirects']
                ) as response:
                    
                    if response.status >= 400:
                        self.metrics['requests_failed'] += 1
                        self.logger.warning(f"Request failed with status {response.status}")
                        if attempt < self.config['max_retries'] - 1:
                            await asyncio.sleep(self.config['retry_delay'])
                            continue
                    
                    try:
                        content = await response.text(encoding='utf-8')
                    except UnicodeDecodeError:
                        content = await response.text(encoding='latin-1')
                        
                    return response, content

            except Exception as e:
                self.metrics['requests_failed'] += 1
                self.logger.error(f"Request error on attempt {attempt + 1}: {str(e)}")
                if attempt < self.config['max_retries'] - 1:
                    await asyncio.sleep(self.config['retry_delay'])
                continue
            finally:
                if session:
                    await self.session_manager.release()

        return None, None

    async def cleanup(self):
        """Enhanced cleanup with better error handling"""
        try:
            # Cleanup scanners first
            if hasattr(self, 'scanners'):
                for scanner_type, scanner in self.scanners.items():
                    try:
                        if hasattr(scanner, 'cleanup'):
                            await scanner.cleanup()
                    except Exception as e:
                        self.log(f"Error cleaning up {scanner_type} scanner: {str(e)}", "ERROR")

            # Cleanup session manager
            if hasattr(self, 'session_manager'):
                try:
                    await self.session_manager.cleanup()
                except Exception as e:
                    self.log(f"Error cleaning up session manager: {str(e)}", "ERROR")

            self._initialized = False
            self.log("Cleanup completed", "INFO")

        except Exception as e:
            self.log(f"Cleanup error: {str(e)}", "ERROR")
        finally:
            # Final cleanup attempt for session manager
            if hasattr(self, 'session_manager'):
                try:
                    await self.session_manager.cleanup()
                except:
                    pass

    async def __aenter__(self):
        if not await self.initialize():
            raise Exception("Scanner initialization failed")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()

    def log(self, message, level='INFO', details=None):
        """Standardized logging method"""
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': level,
            'message': message,
            'details': details,
            'color': self.log_colors.get(level, 'black'),
            'scanner': 'VulnerabilityScanner'
        }
        self.scan_logs.append(log_entry)
        
        # Log to logger with appropriate level
        log_level = getattr(logging, level.upper(), logging.INFO)
        self.logger.log(log_level, message)
        
        # Print to console with color
        print(f"[{level}] {message}")

    def stop(self):
        """Request scan to stop"""
        self._stop_event.set()

    async def should_continue(self):
        """Check if scan should continue"""
        return not self._stop_event.is_set()

    async def run_scanner_on_url(self, check_type, url):
        """Run scanner on specific URL"""
        try:
            scanner = self.scanners[check_type]
            return await scanner.scan(url)
        except Exception as e:
            self.log(f"Error running {check_type} scanner on {url}: {str(e)}", "ERROR")
            return None

    async def verify_vulnerability(self, vulnerability, url):
        """Verify detected vulnerability"""
        try:
            vuln_type = vulnerability.get('type', '').lower()
            details = vulnerability.get('details', {})
            
            # Verify based on vulnerability type
            if vuln_type == 'xss':
                return await self.verify_xss(url, details)
            elif vuln_type == 'sql':
                return await self.verify_sql_injection(url, details)
            elif vuln_type == 'csrf':
                return await self.verify_csrf(url, details)
            
            return True  # Default to true for unverifiable vulnerabilities
            
        except Exception as e:
            self.log(f"Error verifying vulnerability: {str(e)}", "ERROR")
            return False

    async def verify_xss(self, url, details):
        """Verify XSS vulnerability"""
        try:
            payload = details.get('payload')
            if not payload:
                return False
            
            response, content = await self.make_request(url)
            if not content:
                return False
            
            # Check for payload reflection
            if payload in content:
                # Check if payload is properly encoded
                if '&lt;' not in content and '<' in payload:
                    return True
                
            return False
            
        except Exception as e:
            self.log(f"Error verifying XSS: {str(e)}", "ERROR")
            return False

    def process_scan_results(self, results):
        """Enhanced result processing with better categorization and filtering"""
        processed_results = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'info': []
        }
        
        # Add severity scoring
        severity_scores = {
            'Critical': 100,
            'High': 80,
            'Medium': 60,
            'Low': 40,
            'Info': 20
        }
        
        for vuln in results:
            # Add confidence score
            confidence_score = self.calculate_confidence(vuln)
            vuln['confidence_score'] = confidence_score
            
            # Add risk score
            severity = vuln.get('severity', 'Low')
            risk_score = severity_scores.get(severity, 0) * (confidence_score / 100)
            vuln['risk_score'] = risk_score
            
            # Categorize by priority
            if risk_score >= 80:
                processed_results['high_priority'].append(vuln)
            elif risk_score >= 60:
                processed_results['medium_priority'].append(vuln)
            elif risk_score >= 40:
                processed_results['low_priority'].append(vuln)
            else:
                processed_results['info'].append(vuln)
                
        return processed_results

    def calculate_confidence(self, vulnerability):
        """Calculate confidence score for vulnerability"""
        confidence = 100
        
        # Reduce confidence based on various factors
        if not vulnerability.get('proof_of_concept'):
            confidence -= 20
        if not vulnerability.get('verified'):
            confidence -= 30
        if vulnerability.get('false_positive_prone', False):
            confidence -= 25
            
        return max(0, confidence)

    async def log_metrics(self):
        """Log performance metrics"""
        metrics_data = {
            'timestamp': datetime.now().isoformat(),
            'scan_id': self._scan_id,
            'url': self.url,
            'metrics': self.metrics,
            'performance': {
                'memory_usage': psutil.Process().memory_info().rss / 1024 / 1024,
                'cpu_percent': psutil.Process().cpu_percent(),
                'thread_count': threading.active_count()
            }
        }
        
        # Log metrics
        self.logger.info(f"Scan metrics: {json.dumps(metrics_data, indent=2)}")
        
        # Store metrics for analysis
        await self.store_metrics(metrics_data)

    def load_config(self):
        """Load configuration from file with validation"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), 'config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    
                # Validate configuration
                self.validate_config(config)
                self.config.update(config)
            
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            
    def validate_config(self, config):
        """Validate configuration values"""
        required_fields = ['timeout', 'max_retries', 'concurrent_scans']
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required config field: {field}")
                
        if config.get('timeout') < 1:
            raise ValueError("Timeout must be at least 1 second")
