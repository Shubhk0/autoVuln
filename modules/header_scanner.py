from .base_scanner import BaseScanner
import re
from datetime import datetime
import traceback

class HeaderScanner(BaseScanner):
    def __init__(self, session, config):
        super().__init__(session, config)
        
        # Security header definitions
        self.required_headers = {
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-Content-Type-Options': ['nosniff'],
            'X-XSS-Protection': ['1', '1; mode=block'],
            'Strict-Transport-Security': ['max-age='],
            'Content-Security-Policy': [],
            'X-Permitted-Cross-Domain-Policies': ['none'],
            'Referrer-Policy': ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin'],
            'Permissions-Policy': []
        }
        
        # Header recommendations
        self.header_recommendations = {
            'X-Frame-Options': 'Add X-Frame-Options header with DENY or SAMEORIGIN value to prevent clickjacking attacks',
            'X-Content-Type-Options': 'Add X-Content-Type-Options header with nosniff value to prevent MIME type sniffing',
            'X-XSS-Protection': 'Add X-XSS-Protection header with 1; mode=block value to enable browser XSS filtering',
            'Strict-Transport-Security': 'Add Strict-Transport-Security header with appropriate max-age to enforce HTTPS',
            'Content-Security-Policy': 'Implement Content Security Policy to prevent XSS and other injection attacks',
            'X-Permitted-Cross-Domain-Policies': 'Add X-Permitted-Cross-Domain-Policies header to control cross-domain policies',
            'Referrer-Policy': 'Add Referrer-Policy header to control referrer information',
            'Permissions-Policy': 'Implement Permissions-Policy to control browser features'
        }

        # Header severity levels
        self.header_severity = {
            'X-Frame-Options': 'High',
            'X-Content-Type-Options': 'Medium',
            'X-XSS-Protection': 'Medium',
            'Strict-Transport-Security': 'High',
            'Content-Security-Policy': 'High',
            'X-Permitted-Cross-Domain-Policies': 'Medium',
            'Referrer-Policy': 'Medium',
            'Permissions-Policy': 'Low'
        }

    async def scan(self, url):
        """Enhanced security header scanning"""
        try:
            self.log(f"Starting security header scan for {url}", "INFO")

            # Phase 1: Header Collection
            self.log("Phase 1: Collecting headers", "INFO")
            
            # Try multiple request methods with error handling
            response = None
            content = None
            
            # First try HEAD request
            try:
                response, content = await self.make_request(
                    url,
                    method='HEAD',
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': '*/*',
                        'Connection': 'keep-alive'
                    },
                    allow_redirects=True
                )
            except Exception as e:
                self.log(f"HEAD request failed: {str(e)}", "DEBUG")

            # If HEAD fails, try GET
            if not response:
                try:
                    response, content = await self.make_request(
                        url,
                        method='GET',
                        headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                            'Accept': '*/*',
                            'Connection': 'keep-alive'
                        },
                        allow_redirects=True
                    )
                except Exception as e:
                    self.log(f"GET request failed: {str(e)}", "DEBUG")

            if not response:
                self.log("Failed to access target URL", "ERROR")
                return {
                    'vulnerabilities': [],
                    'logs': self.scan_logs,
                    'stats': {
                        'headers_checked': 0,
                        'missing_headers': 0,
                        'misconfigured_headers': 0,
                        'deprecated_headers': 0,
                        'error': 'Failed to access target URL'
                    }
                }

            headers = dict(response.headers)
            self.log(f"Collected {len(headers)} headers", "INFO")

            # Phase 2: Header Analysis
            self.log("Phase 2: Analyzing security headers", "INFO")
            
            # Check missing headers
            missing_headers = self.check_missing_headers(headers)
            for header in missing_headers:
                self.add_vulnerability(
                    type_name="Missing Security Header",
                    description=f"Missing security header: {header}",
                    severity=self.header_severity.get(header, 'Medium'),
                    details={
                        'header': header,
                        'recommendation': self.header_recommendations[header],
                        'url': url
                    }
                )

            # Check misconfigured headers
            misconfigured = self.check_header_values(headers)
            for header, issue in misconfigured.items():
                self.add_vulnerability(
                    type_name="Misconfigured Header",
                    description=f"Misconfigured security header: {header}",
                    severity=self.header_severity.get(header, 'Medium'),
                    details={
                        'header': header,
                        'current_value': headers.get(header),
                        'issue': issue,
                        'recommendation': self.header_recommendations[header],
                        'url': url
                    }
                )

            # Check for deprecated headers
            deprecated = self.check_deprecated_headers(headers)
            for header, reason in deprecated.items():
                self.add_vulnerability(
                    type_name="Deprecated Header",
                    description=f"Deprecated security header in use: {header}",
                    severity="Low",
                    details={
                        'header': header,
                        'reason': reason,
                        'url': url
                    }
                )

            return {
                'vulnerabilities': self.vulnerabilities,
                'logs': self.scan_logs,
                'stats': {
                    'headers_checked': len(headers),
                    'missing_headers': len(missing_headers),
                    'misconfigured_headers': len(misconfigured),
                    'deprecated_headers': len(deprecated)
                }
            }

        except Exception as e:
            self.log(f"Scan error: {str(e)}", "ERROR")
            return {
                'vulnerabilities': [],
                'logs': self.scan_logs,
                'stats': {
                    'headers_checked': 0,
                    'missing_headers': 0,
                    'misconfigured_headers': 0,
                    'deprecated_headers': 0,
                    'error': str(e)
                }
            }

    def check_missing_headers(self, headers):
        """Check for missing security headers"""
        return [
            header for header in self.required_headers.keys()
            if header not in headers
        ]

    def check_header_values(self, headers):
        """Check security header values"""
        issues = {}
        for header, valid_values in self.required_headers.items():
            if header in headers:
                header_value = headers[header].lower()
                if valid_values and not any(val.lower() in header_value for val in valid_values):
                    issues[header] = f"Invalid value: {headers[header]}"
        return issues

    def check_deprecated_headers(self, headers):
        """Check for deprecated security headers"""
        deprecated = {
            'X-WebKit-CSP': 'Use Content-Security-Policy instead',
            'X-Content-Security-Policy': 'Use Content-Security-Policy instead',
            'Public-Key-Pins': 'HPKP is deprecated',
            'Expect-CT': 'Expect-CT is deprecated'
        }
        return {
            header: reason for header, reason in deprecated.items()
            if header in headers
        }

    def analyze_csp(self, csp_value):
        """Analyze Content Security Policy"""
        issues = []
        
        # Check for unsafe directives
        unsafe_directives = ['unsafe-inline', 'unsafe-eval', '*']
        for unsafe in unsafe_directives:
            if unsafe in csp_value.lower():
                issues.append(f"Policy contains unsafe directive: {unsafe}")
                
        # Check for missing essential directives
        essential_directives = ['default-src', 'script-src', 'style-src']
        for directive in essential_directives:
            if directive not in csp_value.lower():
                issues.append(f"Missing essential directive: {directive}")
                
        return issues