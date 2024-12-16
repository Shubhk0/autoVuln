import asyncio
from vulnscan import VulnerabilityScanner
import json
import logging
import sys
from datetime import datetime
import urllib.parse
import os

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
            'ssl': True
        }
        
        # Run scan with timeout
        try:
            results = await asyncio.wait_for(
                scanner.scan(checks),
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

        # Print summary
        try:
            logger.info(f"\nScan Summary for {url}:")
            logger.info("=" * 50)
            
            stats = results.get('stats', {})
            logger.info(f"Total URLs scanned: {stats.get('total_urls', 0)}")
            logger.info(f"Vulnerabilities found: {stats.get('total_vulnerabilities', 0)}")
            logger.info(f"Unique vulnerabilities: {stats.get('unique_vulnerabilities', 0)}")
            
            # Print vulnerabilities by severity
            severity_counts = stats.get('severity_counts', {})
            if severity_counts:
                logger.info("\nVulnerabilities by Severity:")
                for severity, count in severity_counts.items():
                    logger.info(f"{severity}: {count}")
            
            # Print detailed findings
            vulnerabilities = results.get('vulnerabilities', [])
            if vulnerabilities:
                logger.info("\nDetailed Findings:")
                logger.info("=" * 50)
                for vuln in vulnerabilities:
                    logger.info(f"\nType: {vuln.get('type', 'Unknown')}")
                    logger.info(f"Severity: {vuln.get('severity', 'Unknown')}")
                    logger.info(f"Description: {vuln.get('description', 'No description')}")
                    if 'details' in vuln:
                        logger.info("Details:")
                        for key, value in vuln['details'].items():
                            logger.info(f"  {key}: {value}")
            else:
                logger.info("No vulnerabilities found")

        except Exception as e:
            logger.error(f"Error printing results: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error scanning {url}: {str(e)}")
    finally:
        if scanner:
            try:
                await scanner.cleanup()
            except Exception as e:
                logger.error(f"Error during cleanup: {str(e)}")

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
        asyncio.run(run_test_scan())
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")

if __name__ == "__main__":
    main() 