from .base_scanner import BaseScanner
import asyncio
import json
import os
from datetime import datetime
import subprocess
import tempfile

try:
    import yaml
except ImportError:
    yaml = None
    print("[WARNING] PyYAML not installed. Template parsing will be limited. Install with: pip install PyYAML")

class NucleiScanner(BaseScanner):
    def __init__(self, session, config):
        super().__init__(session, config)
        self.nuclei_path = config.get('nuclei_path', 'nuclei')
        self.templates_dir = config.get('templates_dir', './nuclei-templates')
        self.templates = config.get('templates', ['cves', 'vulnerabilities'])
        self.severity_levels = ['critical', 'high', 'medium', 'low', 'info']

    async def scan(self, url):
        """Run Nuclei scan"""
        try:
            self.log(f"Starting Nuclei scan for {url}", "INFO")
            results = []
            
            # Check if Nuclei is installed
            if not await self.check_nuclei_installation():
                self.log("Nuclei not found. Please install nuclei first.", "ERROR")
                return None

            # Create temporary file for results
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                output_file = temp_file.name
                
                # Build nuclei command
                cmd = [
                    self.nuclei_path,
                    '-target', url,
                    '-json',
                    '-output', output_file,
                    '-rate-limit', str(self.config.get('rate_limit', 150)),
                    '-bulk-size', str(self.config.get('bulk_size', 25)),
                    '-retries', str(self.config.get('max_retries', 3)),
                    '-timeout', str(self.config.get('timeout', 5))
                ]
                
                # Add template directories
                for template in self.templates:
                    template_path = os.path.join(self.templates_dir, template)
                    if os.path.exists(template_path):
                        cmd.extend(['-t', template_path])

                # Run nuclei scan
                self.log(f"Running Nuclei command: {' '.join(cmd)}", "DEBUG")
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if stderr:
                    self.log(f"Nuclei stderr: {stderr.decode()}", "ERROR")
                
                # Process results
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        for line in f:
                            try:
                                result = json.loads(line.strip())
                                vuln = self.parse_nuclei_result(result)
                                if vuln:
                                    results.append(vuln)
                            except json.JSONDecodeError:
                                continue
                
                # Cleanup
                os.unlink(output_file)

            self.log(f"Nuclei scan completed. Found {len(results)} vulnerabilities", "INFO")
            return {
                'vulnerabilities': results,
                'logs': self.scan_logs
            }

        except Exception as e:
            self.log(f"Nuclei scan error: {str(e)}", "ERROR")
            return None

    async def check_nuclei_installation(self):
        """Check if nuclei is installed and accessible"""
        try:
            process = await asyncio.create_subprocess_exec(
                self.nuclei_path,
                '-version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                version = stdout.decode().strip()
                self.logger.info(f"Found nuclei version: {version}")
                return True
            else:
                self.logger.error("Nuclei not found or returned error")
                return False
                
        except Exception as e:
            self.logger.error(f"Error checking nuclei installation: {str(e)}")
            return False

    def parse_nuclei_result(self, result):
        """Parse Nuclei result into standard vulnerability format"""
        try:
            if not isinstance(result, dict):
                return None
                
            return {
                'type': 'nuclei',
                'description': result.get('info', {}).get('name', 'Unknown Vulnerability'),
                'severity': result.get('info', {}).get('severity', 'unknown').upper(),
                'details': {
                    'template_id': result.get('template-id'),
                    'template_path': result.get('template'),
                    'matched_at': result.get('matched-at'),
                    'matcher_name': result.get('matcher-name'),
                    'extracted_results': result.get('extracted-results', []),
                    'curl_command': result.get('curl-command'),
                    'type': result.get('type'),
                    'host': result.get('host'),
                    'protocol': result.get('protocol'),
                    'reference': result.get('info', {}).get('reference', []),
                    'tags': result.get('info', {}).get('tags', [])
                },
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing Nuclei result: {str(e)}")
            return None

    async def update_templates(self):
        """Update Nuclei templates"""
        try:
            self.logger.info("Updating Nuclei templates")
            
            cmd = [self.nuclei_path, '-update-templates']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self.logger.info("Templates updated successfully")
            else:
                self.logger.error(f"Template update failed: {stderr.decode()}")
                
        except Exception as e:
            self.logger.error(f"Error updating templates: {str(e)}") 