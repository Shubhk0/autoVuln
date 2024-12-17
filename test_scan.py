import asyncio
from vulnscan import VulnerabilityScanner
import json
import logging
import sys
from datetime import datetime
import urllib.parse
import os

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def format_severity(severity):
    """Format severity with color"""
    if severity == 'Critical':
        return f"{Colors.RED}{severity}{Colors.ENDC}"
    elif severity == 'High':
        return f"{Colors.YELLOW}{severity}{Colors.ENDC}"
    else:
        return f"{Colors.CYAN}{severity}{Colors.ENDC}"

def print_section_header(title):
    """Print a formatted section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 50}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}{title}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 50}{Colors.ENDC}")

def print_subsection_header(title):
    """Print a formatted subsection header"""
    print(f"\n{Colors.CYAN}{title}{Colors.ENDC}")
    print(f"{Colors.CYAN}{'-' * 30}{Colors.ENDC}")

def validate_url(url):
    """Validate URL format and accessibility"""
    try:
        # Check URL format
        if not url.startswith(('http://', 'https://')):
            return False, "URL must start with http:// or https://"
            
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return False, "Invalid URL format"
            
        # Additional checks
        if any(c in url for c in ['<', '>', '"', "'", ';', '(', ')', '{', '}']):
            return False, "URL contains invalid characters"
            
        return True, None
        
    except Exception as e:
        return False, f"URL validation error: {str(e)}"

async def scan_site(url):
    """Scan a single site with error handling"""
    scanner = None
    try:
        # Validate URL
        valid, error = validate_url(url)
        if not valid:
            logger.error(f"Invalid URL {url}: {error}")
            return
        
        logger.info(f"\nStarting comprehensive scan of {url}")
        logger.info("=" * 50)
        
        # Initialize scanner with retry logic
        for attempt in range(3):
            try:
                scanner = VulnerabilityScanner(url)
                break
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed to initialize scanner: {str(e)}")
                if attempt == 2:  # Last attempt
                    raise
                await asyncio.sleep(1)

        # Configure scan checks
        checks = {
            'xss': True,
            'sql': True,
            'csrf': True,
            'headers': True,
            'ssl': True,
            'clickjacking': True
        }
        
        # Run scan with timeout
        try:
            results = await asyncio.wait_for(
                scanner.run_scan(checks),  
                timeout=300  # 5 minutes timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Scan timeout for {url}")
            return
        
        if not results:
            logger.error(f"No results returned for {url}")
            return

        # Save results
        try:
            os.makedirs('results', exist_ok=True)
            filename = f'results/scan_results_{url.replace("http://", "").replace(".", "_")}.json'
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")

        # Print scan summary
        print_section_header(f"Scan Summary for {url}")
        print(f"{Colors.BOLD}Status:{Colors.ENDC} {results.get('status', 'unknown')}")
        print(f"{Colors.BOLD}Start Time:{Colors.ENDC} {results.get('start_time')}")
        print(f"{Colors.BOLD}End Time:{Colors.ENDC} {results.get('end_time')}")
        
        print_subsection_header("Metrics")
        metrics = results.get('metrics', {})
        print(f"{Colors.BOLD}Total Requests:{Colors.ENDC} {metrics.get('requests_made', 0)}")
        print(f"{Colors.BOLD}Failed Requests:{Colors.ENDC} {metrics.get('requests_failed', 0)}")
        print(f"{Colors.BOLD}Vulnerabilities Found:{Colors.ENDC} {metrics.get('vulnerabilities_found', 0)}")
        
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            print_section_header("Vulnerabilities Found")
            
            # Group vulnerabilities by type
            vuln_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type')
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(vuln)
            
            # Print each vulnerability type
            for vuln_type, vulns in vuln_types.items():
                print_subsection_header(f"{vuln_type} Vulnerabilities")
                for vuln in vulns:
                    print(f"\n{Colors.BOLD}Type:{Colors.ENDC} {vuln.get('type')}")
                    print(f"{Colors.BOLD}Severity:{Colors.ENDC} {format_severity(vuln.get('severity', 'Unknown'))}")
                    print(f"{Colors.BOLD}Description:{Colors.ENDC} {vuln.get('description', 'No description')}")
                    
                    # Format evidence based on type
                    if 'evidence' in vuln:
                        print(f"{Colors.BOLD}Evidence:{Colors.ENDC}")
                        for key, value in vuln['evidence'].items():
                            print(f"  - {key}: {value}")
        else:
            print(f"\n{Colors.GREEN}No vulnerabilities found{Colors.ENDC}")
            
    except Exception as e:
        logger.error(f"Error scanning {url}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        if scanner:
            await scanner.close_session()
            logger.info("Session cleanup completed")

async def run_test_scan():
    """Run test scans on multiple sites"""
    test_sites = [
        "http://testphp.vulnweb.com",
        "http://zero.webappsecurity.com"
    ]
    
    for url in test_sites:
        await scan_site(url)

def main():
    try:
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        logger = logging.getLogger(__name__)
        
        asyncio.run(run_test_scan())
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")

if __name__ == "__main__":
    main()