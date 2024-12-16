from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Scan
from vulnscan import VulnerabilityScanner
import threading
import queue
import json
from datetime import datetime
import uuid
import asyncio
import traceback
import os
from flask_talisman import Talisman
import secrets
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf
import urllib.parse
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import atexit

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Add CSRF token to all templates
@app.context_processor
def utility_processor():
    def get_csrf_token():
        token = generate_csrf()
        return token
    return {
        'get_csrf_token': get_csrf_token,
        'csp_nonce': lambda: secrets.token_hex(16)
    }

# Add security headers
Talisman(app, 
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
        'style-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
        'font-src': ["'self'", "cdn.jsdelivr.net"],
        'img-src': ["'self'", "data:", "cdn.jsdelivr.net"],
    },
    force_https=False  # Set to True in production
)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create database tables
with app.app_context():
    db.create_all()
    # Create admin user if it doesn't exist
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin = User(
            username='admin',
            email='admin@example.com',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Store scan results in memory (consider moving to database)
scan_results = {}

# Add a background task manager
class BackgroundTaskManager:
    def __init__(self):
        self.tasks = {}
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.lock = threading.Lock()

    def add_task(self, scan_id, task):
        with self.lock:
            self.tasks[scan_id] = task

    def get_task(self, scan_id):
        with self.lock:
            return self.tasks.get(scan_id)

    def remove_task(self, scan_id):
        with self.lock:
            if scan_id in self.tasks:
                del self.tasks[scan_id]

# Initialize task manager
task_manager = BackgroundTaskManager()

# Authentication routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('index'))
            
        flash('Invalid username or password')
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Protected routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
@login_required
def start_scan():
    try:
        # Get CSRF token from header
        token = request.headers.get('X-CSRF-Token')
        if not token:
            print("[DEBUG] Missing CSRF token in headers")
            return jsonify({'error': 'Missing CSRF token'}), 403
            
        try:
            validate_csrf(token)
            print("[DEBUG] CSRF token validated successfully")
        except Exception as e:
            print(f"[DEBUG] CSRF validation failed: {str(e)}")
            return jsonify({'error': 'Invalid CSRF token'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        url = data.get('url', '').strip()
        checks = data.get('checks', {})
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Validate and normalize URL
        try:
            # Remove whitespace and convert to lowercase
            url = url.strip().lower()
            
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                print(f"[DEBUG] Added http:// to URL: {url}")
            
            # Parse and validate URL
            parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.netloc:
                return jsonify({'error': 'Invalid URL: Missing domain'}), 400
            
            # Remove trailing slash
            url = url.rstrip('/')
            print(f"[DEBUG] Final normalized URL: {url}")
            
            # Basic validation of domain format
            domain = parsed_url.netloc
            if not '.' in domain or len(domain.split('.')[-1]) < 2:
                return jsonify({'error': 'Invalid domain format'}), 400
            
        except Exception as e:
            print(f"[DEBUG] URL validation error: {str(e)}")
            return jsonify({'error': f'Invalid URL format: {str(e)}'}), 400
        
        print(f"[DEBUG] Starting scan for validated URL: {url}")
        
        # Validate and normalize checks
        valid_checks = {
            'xss': True,
            'sql': True,
            'csrf': True,
            'headers': True,
            'ssl': True,
            'clickjacking': True
        }
        
        # If no checks specified, enable all
        if not checks:
            checks = valid_checks
        else:
            # Ensure only valid checks are included
            checks = {k: bool(v) for k, v in checks.items() if k in valid_checks}
        
        # Create scan ID and initialize scan
        scan_id = str(uuid.uuid4())
        
        # Create scan record in database
        scan = Scan(
            scan_id=scan_id,
            url=url,
            status='running',
            user_id=current_user.id,
            result={
                'status': 'running',
                'current_stage': 'Initializing scan...',
                'progress': 0,
                'checks': checks,
                'vulnerabilities': [],
                'scan_type': 'Quick Scan' if all(checks.values()) else 'Custom Scan',
                'enabled_checks': [k for k, v in checks.items() if v]
            }
        )
        db.session.add(scan)
        db.session.commit()
        
        # Start scan in background
        task = task_manager.executor.submit(run_scan_in_background, scan_id, url, checks)
        task_manager.add_task(scan_id, task)
        
        return jsonify({
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        print(f"[DEBUG] Error starting scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

def run_scan_in_background(scan_id, url, checks):
    """Run scan in background thread"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run the scan
        scanner = VulnerabilityScanner(url)
        results = loop.run_until_complete(scanner.scan(checks))
        
        # Update database with results
        with app.app_context():
            scan = Scan.query.filter_by(scan_id=scan_id).first()
            if scan:
                scan.status = 'completed'
                scan.result.update(results)
                db.session.commit()
        
        loop.close()
        
    except Exception as e:
        print(f"[DEBUG] Background scan error: {str(e)}")
        # Update database with error
        with app.app_context():
            scan = Scan.query.filter_by(scan_id=scan_id).first()
            if scan:
                scan.status = 'error'
                scan.result['error'] = str(e)
                db.session.commit()
    finally:
        task_manager.remove_task(scan_id)

@app.route('/status/<scan_id>')
def get_status(scan_id):
    try:
        scan = Scan.query.filter_by(scan_id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        # Get task status
        task = task_manager.get_task(scan_id)
        if task:
            if task.done():
                if task.exception():
                    return jsonify({
                        'status': 'error',
                        'error': str(task.exception())
                    })
            elif task.running():
                scan.result['status'] = 'running'

        return jsonify({
            'status': scan.status,
            'progress': scan.result.get('progress', 0),
            'current_stage': scan.result.get('current_stage', 'Initializing...'),
            'vulnerabilities': scan.result.get('vulnerabilities', []),
            'url': scan.url,
            'stats': scan.result.get('stats', {})
        })

    except Exception as e:
        print(f"Error getting scan status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/reports')
@login_required
def view_reports():
    try:
        if current_user.is_admin:
            scans = Scan.query.order_by(Scan.timestamp.desc()).all()
        else:
            scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).all()
        
        # Convert scans to list of dictionaries with all required fields
        reports = []
        for scan in scans:
            report = {
                'scan_id': scan.scan_id,
                'url': scan.url,
                'timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'status': scan.status,
                'vulnerabilities': [],
                'user_id': scan.user_id
            }
            
            # Get vulnerabilities from scan result
            if scan.result and 'vulnerabilities' in scan.result:
                report['vulnerabilities'] = scan.result['vulnerabilities']
            
            reports.append(report)
        
        print(f"[DEBUG] Found {len(reports)} reports")
        for report in reports:
            print(f"[DEBUG] Report: {report['url']} - {len(report['vulnerabilities'])} vulnerabilities")
        
        return render_template('reports.html', reports=reports)
        
    except Exception as e:
        print(f"[DEBUG] Error in view_reports: {str(e)}")
        flash('Error loading reports', 'danger')
        return redirect(url_for('index'))

@app.route('/report/<scan_id>')
@login_required
def view_report(scan_id):
    try:
        scan = Scan.query.filter_by(scan_id=scan_id).first()
        if not scan:
            flash('Report not found', 'error')
            return redirect(url_for('view_reports'))
            
        # Check if user has permission to view this scan
        if not current_user.is_admin and scan.user_id != current_user.id:
            flash('Permission denied', 'error')
            return redirect(url_for('view_reports'))
            
        # Prepare report data
        report = {
            'scan_id': scan.scan_id,
            'url': scan.url,
            'timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'status': scan.status,
            'vulnerabilities': [],
            'scan_type': scan.result.get('scan_type', 'Unknown Scan'),
            'enabled_checks': scan.result.get('enabled_checks', []),
            'logs': scan.result.get('logs', []),  # Add logs
            'stats': {
                'duration': scan.result.get('stats', {}).get('duration', 0),
                'modules_completed': scan.result.get('stats', {}).get('modules_completed', []),
                'total_modules': scan.result.get('stats', {}).get('total_modules', 0),
                'errors': scan.result.get('stats', {}).get('errors', []),
                'vulnerabilities_found': 0
            }
        }
        
        # Get vulnerabilities from scan result
        if scan.result and 'vulnerabilities' in scan.result:
            report['vulnerabilities'] = scan.result['vulnerabilities']
            report['stats']['vulnerabilities_found'] = len(report['vulnerabilities'])
            
        return render_template('report_detail.html', report=report)
        
    except Exception as e:
        print(f"[DEBUG] Error viewing report: {str(e)}")
        flash('Error loading report', 'error')
        return redirect(url_for('view_reports'))

@app.route('/test_scan/<scanner_type>')
def test_scanner(scanner_type):
    """Test route for individual scanner functionality"""
    try:
        # Test against known vulnerable endpoints
        test_urls = [
            "http://testphp.vulnweb.com/search.php?test=query",
            "http://testphp.vulnweb.com/artists.php?artist=1",
            "http://testphp.vulnweb.com/guestbook.php",
            "http://testphp.vulnweb.com/login.php"
        ]
        
        results = []
        for url in test_urls:
            scanner = VulnerabilityScanner(url)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            async def run_test():
                await scanner.initialize()
                print(f"\n[DEBUG] Testing scanner against {url}")
                
                if scanner_type == 'all':
                    checks = {
                        'xss': True,
                        'sql': True,
                        'csrf': True,
                        'headers': True,
                        'ssl': True
                    }
                    return await scanner.scan(checks)
                elif scanner_type in scanner.scanners:
                    test_scanner = scanner.scanners[scanner_type]
                    print(f"[DEBUG] Running {scanner_type} scanner...")
                    await test_scanner.scan(url)
                    vulns = test_scanner.vulnerabilities
                    print(f"[DEBUG] Found {len(vulns)} vulnerabilities")
                    for vuln in vulns:
                        print(f"\n[DEBUG] Vulnerability Details:")
                        print(f"Description: {vuln.get('description')}")
                        print(f"Severity: {vuln.get('severity')}")
                    return {
                        'scanner': scanner_type,
                        'url': url,
                        'vulnerabilities': vulns
                    }
                else:
                    return {'error': 'Invalid scanner type'}
            
            result = loop.run_until_complete(run_test())
            results.append(result)
            
        return jsonify({'results': results})
        
    except Exception as e:
        print(f"[DEBUG] Error in test_scanner: {str(e)}")
        print(f"[DEBUG] Traceback: {traceback.format_exc()}")
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        })

@app.route('/test_vulnerability')
def test_vulnerability():
    """Test route that is intentionally vulnerable to XSS"""
    xss_param = request.args.get('xss', '')
    return f'''
    <html>
        <body>
            <h1>Test Page</h1>
            <div>{xss_param}</div>
        </body>
    </html>
    '''

@app.route('/reports/delete', methods=['POST'])
@login_required
@csrf.exempt  # If you want to handle CSRF manually through headers
def delete_reports():
    try:
        data = request.get_json()
        if not data or 'password' not in data:
            return jsonify({
                'success': False,
                'message': 'Password is required'
            }), 400
        
        # Verify CSRF token
        token = request.headers.get('X-CSRF-Token')
        if not token or not validate_csrf(token):
            return jsonify({
                'success': False,
                'message': 'Invalid CSRF token'
            }), 403
            
        password = data['password']
        
        # Verify user's password
        if not current_user.check_password(password):
            return jsonify({
                'success': False,
                'message': 'Invalid password'
            }), 403
        
        deleted_count = 0
        try:
            # Only admin can delete all reports, regular users can only delete their own
            if current_user.is_admin:
                deleted_count = Scan.query.delete()
            else:
                deleted_count = Scan.query.filter_by(user_id=current_user.id).delete()
            
            # Clear in-memory results
            scan_results.clear()
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Successfully deleted {deleted_count} reports',
                'deleted_count': deleted_count
            })
            
        except Exception as e:
            db.session.rollback()
            raise
        
    except Exception as e:
        print(f"Error deleting reports: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while deleting reports'
        }), 500

@app.route('/reports/delete/<scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    try:
        print(f"[DEBUG] Attempting to delete scan: {scan_id}")
        
        # Verify CSRF token
        token = request.headers.get('X-CSRF-Token')
        if not token:
            print("[DEBUG] Missing CSRF token")
            return jsonify({
                'success': False,
                'message': 'Missing CSRF token'
            }), 403
            
        try:
            validate_csrf(token)
            print("[DEBUG] CSRF token validated")
        except Exception as e:
            print(f"[DEBUG] CSRF validation failed: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'Invalid CSRF token'
            }), 403
        
        # Get the scan
        scan = Scan.query.filter_by(scan_id=scan_id).first()
        if not scan:
            print(f"[DEBUG] Scan not found: {scan_id}")
            return jsonify({
                'success': False,
                'message': 'Scan not found'
            }), 404
            
        print(f"[DEBUG] Found scan: {scan.scan_id}, user_id: {scan.user_id}")
        
        # Check if user has permission to delete this scan
        if not current_user.is_admin and scan.user_id != current_user.id:
            print(f"[DEBUG] Permission denied. User: {current_user.id}, Scan owner: {scan.user_id}")
            return jsonify({
                'success': False,
                'message': 'Permission denied'
            }), 403
            
        try:
            # Delete the scan
            db.session.delete(scan)
            
            # Remove from in-memory results if exists
            if scan_id in scan_results:
                del scan_results[scan_id]
            
            db.session.commit()
            print(f"[DEBUG] Successfully deleted scan: {scan_id}")
            
            return jsonify({
                'success': True,
                'message': 'Scan deleted successfully',
                'scan_id': scan_id
            })
            
        except Exception as e:
            db.session.rollback()
            print(f"[DEBUG] Database error: {str(e)}")
            raise
        
    except Exception as e:
        print(f"[DEBUG] Error deleting scan: {str(e)}")
        print(f"[DEBUG] Traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while deleting the scan'
        }), 500

class ScanStatus(Enum):
    RUNNING = 'running'
    PAUSED = 'paused'
    COMPLETED = 'completed'
    ERROR = 'error'

@app.route('/scan/<scan_id>/toggle_pause', methods=['POST'])
@login_required
def toggle_scan_pause(scan_id):
    try:
        scan = Scan.query.filter_by(scan_id=scan_id).first()
        if not scan:
            return jsonify({
                'success': False,
                'message': 'Scan not found'
            }), 404

        # Check permissions
        if not current_user.is_admin and scan.user_id != current_user.id:
            return jsonify({
                'success': False,
                'message': 'Permission denied'
            }), 403

        # Toggle pause state
        current_status = scan.result.get('status', 'running')
        new_status = 'paused' if current_status == 'running' else 'running'
        
        # Update scan status
        scan.result['status'] = new_status
        scan.status = new_status
        db.session.commit()

        # Update in-memory results if they exist
        if scan_id in scan_results:
            scan_results[scan_id]['status'] = new_status

        return jsonify({
            'success': True,
            'status': new_status,
            'message': f'Scan {new_status}'
        })

    except Exception as e:
        print(f"[DEBUG] Error toggling scan pause: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error toggling scan state'
        }), 500

@app.route('/scan/<scan_id>/logs')
@login_required
def get_scan_logs(scan_id):
    try:
        scan = Scan.query.filter_by(scan_id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
            
        # Check permissions
        if not current_user.is_admin and scan.user_id != current_user.id:
            return jsonify({'error': 'Permission denied'}), 403
            
        # Get logs from scan result
        logs = scan.result.get('logs', [])
        status = scan.status
        
        return jsonify({
            'logs': logs,
            'status': status
        })
        
    except Exception as e:
        print(f"[DEBUG] Error getting scan logs: {str(e)}")
        return jsonify({'error': 'Error retrieving logs'}), 500

# Add cleanup on shutdown
@atexit.register
def cleanup():
    task_manager.executor.shutdown(wait=True)

if __name__ == '__main__':
    app.run(debug=True) 