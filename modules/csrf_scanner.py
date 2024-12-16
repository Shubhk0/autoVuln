from .base_scanner import BaseScanner
from bs4 import BeautifulSoup
import urllib.parse
from datetime import datetime
import traceback

class CSRFScanner(BaseScanner):
    def __init__(self, session, config):
        super().__init__(session, config)
        # Common CSRF token field names
        self.csrf_fields = [
            'csrf', 'csrftoken', 'csrf_token', 'csrf-token',
            '_csrf', '_csrftoken', '_csrf_token', '_token',
            'authenticity_token', 'xsrf', 'xsrf_token'
        ]

    async def scan(self, url):
        """Enhanced CSRF scanning"""
        try:
            self.log(f"Starting CSRF scan for {url}", "INFO")
            results = []

            # Phase 1: Initial Page Access
            self.log("Phase 1: Accessing target page", "INFO")
            response, content = await self.make_request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive'
                },
                allow_redirects=True
            )

            if not response or not content:
                self.log("Failed to access target URL", "ERROR")
                return {
                    'vulnerabilities': [],
                    'logs': self.scan_logs,
                    'stats': {
                        'forms_checked': 0,
                        'vulnerabilities_found': 0,
                        'error': 'Failed to access target URL'
                    }
                }

            # Phase 2: Form Analysis
            self.log("Phase 2: Analyzing forms", "INFO")
            soup = BeautifulSoup(content, 'html.parser')
            forms = soup.find_all('form')
            
            self.log(f"Found {len(forms)} forms to analyze", "INFO")
            forms_checked = 0
            vulnerable_forms = 0

            # Phase 3: Form Testing
            self.log("Phase 3: Testing forms for CSRF vulnerabilities", "INFO")
            for form in forms:
                try:
                    form_method = form.get('method', 'get').upper()
                    
                    # Only test POST forms
                    if form_method != 'POST':
                        self.log(f"Skipping {form_method} form", "DEBUG")
                        continue

                    forms_checked += 1
                    form_results = await self.test_form(url, form)
                    
                    if form_results:
                        vulnerable_forms += 1
                        results.extend(form_results)
                        
                except Exception as e:
                    self.log(f"Error testing form: {str(e)}", "ERROR")
                    continue

            # Phase 4: Results Analysis
            self.log("Phase 4: Analyzing results", "INFO")
            if results:
                self.log(f"Found {len(results)} CSRF vulnerabilities", "WARNING")
            else:
                self.log("No CSRF vulnerabilities found", "INFO")

            return {
                'vulnerabilities': results,
                'logs': self.scan_logs,
                'stats': {
                    'forms_checked': forms_checked,
                    'vulnerable_forms': vulnerable_forms,
                    'total_forms': len(forms),
                    'completion_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            }

        except Exception as e:
            self.log(f"Scan error: {str(e)}", "ERROR")
            return {
                'vulnerabilities': [],
                'logs': self.scan_logs,
                'stats': {
                    'forms_checked': 0,
                    'vulnerabilities_found': 0,
                    'error': str(e)
                }
            }

    async def test_form(self, url, form):
        """Test a form for CSRF vulnerabilities"""
        try:
            results = []
            
            # Get form details
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            
            # Only check POST forms
            if method != 'POST':
                return results

            # Build full action URL
            if action:
                if action.startswith('/'):
                    parsed_url = urllib.parse.urlparse(url)
                    action_url = f"{parsed_url.scheme}://{parsed_url.netloc}{action}"
                elif not action.startswith(('http://', 'https://')):
                    action_url = urllib.parse.urljoin(url, action)
                else:
                    action_url = action
            else:
                action_url = url

            self.log(f"Testing form at {action_url}", "DEBUG")

            # Check for CSRF protection
            has_csrf_token = await self.check_csrf_protection(form)
            
            if not has_csrf_token:
                # Verify the vulnerability
                if await self.verify_csrf_vulnerability(action_url, form):
                    self.add_vulnerability(
                        type_name="CSRF",
                        description="Form vulnerable to CSRF attack",
                        severity="High",
                        details={
                            'url': action_url,
                            'form_method': method,
                            'form_action': action,
                            'missing_protection': 'No CSRF token found',
                            'recommendation': 'Implement CSRF token protection'
                        }
                    )
                    results.append({
                        'type': 'CSRF',
                        'url': action_url,
                        'severity': 'High',
                        'description': 'Form vulnerable to CSRF attack',
                        'details': {
                            'form_method': method,
                            'form_action': action,
                            'missing_protection': 'No CSRF token found'
                        }
                    })

            return results

        except Exception as e:
            self.log(f"Error testing form: {str(e)}", "ERROR")
            return []

    async def check_csrf_protection(self, form):
        """Check for CSRF protection mechanisms"""
        try:
            # Check hidden inputs for CSRF token
            hidden_inputs = form.find_all('input', type='hidden')
            for input_field in hidden_inputs:
                input_name = input_field.get('name', '').lower()
                if any(token_name in input_name for token_name in self.csrf_fields):
                    return True

            # Check meta tags
            meta_tokens = form.find_all('meta', attrs={'name': lambda x: x and any(
                token_name in x.lower() for token_name in self.csrf_fields
            )})
            if meta_tokens:
                return True

            return False

        except Exception as e:
            self.log(f"Error checking CSRF protection: {str(e)}", "ERROR")
            return False

    async def verify_csrf_vulnerability(self, url, form):
        """Verify CSRF vulnerability by testing form submission"""
        try:
            # Prepare form data
            form_data = {}
            for input_field in form.find_all(['input', 'textarea']):
                name = input_field.get('name')
                if name:
                    value = input_field.get('value', '')
                    if isinstance(value, list):
                        value = value[0] if value else ''
                    form_data[name] = value

            # Test submission from different origin
            test_headers = {
                'Origin': 'http://attacker.com',
                'Referer': 'http://attacker.com/csrf.html',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive'
            }

            # Make the request
            response, _ = await self.make_request(
                url=url,
                method='POST',
                data=form_data,
                headers=test_headers,
                allow_redirects=True
            )

            # Check if submission was successful
            return response and response.status == 200

        except Exception as e:
            self.log(f"Error verifying CSRF vulnerability: {str(e)}", "ERROR")
            return False

    def add_vulnerability(self, description, severity):
        """Add a vulnerability to the list"""
        vuln = {
            'type': 'CSRF',
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        self.vulnerabilities.append(vuln)
        self.logger.warning(f"Found CSRF vulnerability: {description}")