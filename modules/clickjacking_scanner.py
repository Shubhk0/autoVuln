from .base_scanner import BaseScanner

class ClickjackingScanner(BaseScanner):
    async def scan(self, url, method='GET'):
        await self.log_progress(f"Checking clickjacking protections for {url}")
        try:
            response, content = await self.make_request(url, method)
            if response:
                headers = response.headers
                
                # Check X-Frame-Options header
                if 'X-Frame-Options' not in headers:
                    self.add_vulnerability(
                        "Missing X-Frame-Options header - vulnerable to clickjacking",
                        "Medium"
                    )
                else:
                    x_frame = headers['X-Frame-Options'].upper()
                    if x_frame not in ['DENY', 'SAMEORIGIN']:
                        self.add_vulnerability(
                            f"Weak X-Frame-Options configuration: {x_frame}",
                            "Medium"
                        )
                
                # Check CSP frame-ancestors
                if 'Content-Security-Policy' in headers:
                    csp = headers['Content-Security-Policy']
                    if 'frame-ancestors' not in csp:
                        self.add_vulnerability(
                            "CSP missing frame-ancestors directive",
                            "Low"
                        )

                await self.log_success(f"Completed clickjacking scan for {url}")
                
        except Exception as e:
            await self.log_error(f"Error during clickjacking scan: {str(e)}") 