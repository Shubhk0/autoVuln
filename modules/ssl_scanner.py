from .base_scanner import BaseScanner
import ssl
import socket
from datetime import datetime, timedelta
import urllib.parse
import aiohttp
import time

class SSLScanner(BaseScanner):
    def __init__(self, session, config):
        super().__init__(session, config)
        self.ssl_issues = []

    async def scan(self, url):
        """Scan for SSL/TLS vulnerabilities"""
        try:
            self.log(f"Starting SSL scan for {url}", "INFO")
            results = []
            
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)

            # Check SSL/TLS configuration
            ssl_context = await self.check_ssl_configuration(hostname, port)
            if ssl_context:
                for issue in ssl_context:
                    self.add_vulnerability(
                        type_name="SSL Configuration",
                        description=issue['description'],
                        severity=issue['severity'],
                        details={
                            'hostname': hostname,
                            'port': port,
                            'issue_type': issue['type'],
                            'recommendation': issue.get('recommendation', '')
                        }
                    )

            # Check certificate
            cert_issues = await self.check_certificate(hostname, port)
            if cert_issues:
                for issue in cert_issues:
                    self.add_vulnerability(
                        type_name="SSL Certificate",
                        description=issue['description'],
                        severity=issue['severity'],
                        details={
                            'hostname': hostname,
                            'port': port,
                            'issue_type': issue['type'],
                            'recommendation': issue.get('recommendation', '')
                        }
                    )

            return {
                'vulnerabilities': self.vulnerabilities,
                'logs': self.scan_logs
            }

        except Exception as e:
            self.log(f"Error in SSL scan: {str(e)}", "ERROR")
            return None

    async def check_ssl_configuration(self, hostname, port):
        """Check SSL/TLS configuration"""
        issues = []
        try:
            # Test for SSL v2 and v3 (deprecated)
            if await self.test_ssl_version(hostname, port, 'SSLv2'):
                issues.append({
                    'type': 'deprecated_protocol',
                    'severity': 'High',
                    'description': 'Server supports SSLv2 which is deprecated and insecure',
                    'recommendation': 'Disable SSLv2 support on the server'
                })

            if await self.test_ssl_version(hostname, port, 'SSLv3'):
                issues.append({
                    'type': 'deprecated_protocol',
                    'severity': 'High',
                    'description': 'Server supports SSLv3 which is deprecated and insecure',
                    'recommendation': 'Disable SSLv3 support on the server'
                })

            # Test for weak ciphers
            weak_ciphers = await self.test_weak_ciphers(hostname, port)
            if weak_ciphers:
                issues.append({
                    'type': 'weak_ciphers',
                    'severity': 'Medium',
                    'description': f'Server supports weak ciphers: {", ".join(weak_ciphers)}',
                    'recommendation': 'Disable weak cipher suites'
                })

            return issues

        except Exception as e:
            self.log(f"Error checking SSL configuration: {str(e)}", "ERROR")
            return []

    async def check_certificate(self, hostname, port):
        """Check SSL certificate issues"""
        issues = []
        try:
            cert_info = await self.get_certificate_info(hostname, port)
            if cert_info:
                # Check expiration
                if cert_info.get('expired'):
                    issues.append({
                        'type': 'expired_cert',
                        'severity': 'Critical',
                        'description': 'SSL certificate has expired',
                        'recommendation': 'Renew the SSL certificate'
                    })

                # Check self-signed
                if cert_info.get('self_signed'):
                    issues.append({
                        'type': 'self_signed_cert',
                        'severity': 'High',
                        'description': 'Server is using a self-signed certificate',
                        'recommendation': 'Use a certificate from a trusted CA'
                    })

                # Check hostname mismatch
                if not cert_info.get('hostname_match'):
                    issues.append({
                        'type': 'hostname_mismatch',
                        'severity': 'High',
                        'description': 'Certificate hostname does not match server hostname',
                        'recommendation': 'Use a certificate with correct hostname'
                    })

            return issues

        except Exception as e:
            self.log(f"Error checking certificate: {str(e)}", "ERROR")
            return []

    async def test_ssl_version(self, hostname, port, version):
        """Test if server supports specific SSL version"""
        try:
            context = ssl.SSLContext(getattr(ssl, version))
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(f"https://{hostname}:{port}", ssl=context) as response:
                        return True
                except:
                    return False
        except:
            return False

    async def test_weak_ciphers(self, hostname, port):
        """Test for weak cipher support"""
        weak_ciphers = []
        try:
            # List of known weak ciphers
            test_ciphers = [
                'NULL', 'aNULL', 'eNULL', 'ADH', 'EXP', 'DES', 'RC4', 'MD5'
            ]
            
            for cipher in test_ciphers:
                if await self.test_cipher(hostname, port, cipher):
                    weak_ciphers.append(cipher)
                    
            return weak_ciphers
            
        except Exception as e:
            self.log(f"Error testing weak ciphers: {str(e)}", "ERROR")
            return []

    async def get_certificate_info(self, hostname, port):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'expired': ssl.cert_time_to_seconds(cert['notAfter']) < time.time(),
                        'self_signed': dict(cert['subject']) == dict(cert['issuer']),
                        'hostname_match': ssl.match_hostname(cert, hostname)
                    }
                    
        except Exception as e:
            self.log(f"Error getting certificate info: {str(e)}", "ERROR")
            return None 