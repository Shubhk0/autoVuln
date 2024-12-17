from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from models import db, User, Scan, ScanResult
from vulnscan import VulnerabilityScanner
from flask_wtf.csrf import CSRFProtect, generate_csrf
from urllib.parse import urlparse
import json
import logging
import asyncio
import threading
import os
import re
from datetime import datetime as dt
from fpdf import FPDF

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnscan.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize extensions
    db.init_app(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    csrf = CSRFProtect(app)
    
    # Make csrf_token available to all templates
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf())
        
    with app.app_context():
        # Create database tables
        inspector = db.inspect(db.engine)
        if not inspector.has_table('user'):
            db.create_all()
            
            # Create admin user if it doesn't exist
            admin = User(username='admin', email='admin@example.com', is_admin=True)
            admin.set_password('admin')  # Change this password in production
            db.session.add(admin)
            db.session.commit()
    
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @app.route('/')
    @login_required
    def index():
        """Render the security scanner form"""
        return render_template('security_scanner.html')

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
            return redirect(url_for('login'))
            
        return render_template('login.html')

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

    @app.route('/start_scan', methods=['POST'])
    @login_required
    def start_scan():
        """Start a new vulnerability scan"""
        try:
            data = request.get_json()
            if not data:
                logger.error("Invalid request data: No JSON data received")
                return jsonify({'error': 'Invalid request data'}), 400
                
            url = data.get('url')
            checks = data.get('checks', [])
            
            if not url:
                logger.error("Invalid request data: No URL provided")
                return jsonify({'error': 'URL is required'}), 400
                
            # Validate checks
            valid_checks = {'xss', 'sql', 'cmd', 'ssrf'}
            if not all(check in valid_checks for check in checks):
                logger.error(f"Invalid scanner types requested: {checks}")
                return jsonify({'error': 'Invalid scanner types'}), 400
                
            # Create scan record
            scan = Scan(
                url=url,
                user_id=current_user.id,
                status='pending',
                start_time=dt.now(timezone.utc)
            )
            db.session.add(scan)
            db.session.commit()
            
            # Start scan in background
            thread = threading.Thread(
                target=run_scan_in_background,
                args=(scan.id, url, checks)
            )
            thread.daemon = True
            thread.start()
            
            logger.info(f"Scan started successfully with ID: {scan.id}")
            return jsonify({
                'scan_id': scan.id,
                'message': 'Scan started successfully'
            })
            
        except Exception as e:
            logger.error(f"Error starting scan: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/scan/<int:scan_id>/status')
    @login_required
    def get_scan_status(scan_id):
        """Get the status of a specific scan with enhanced details"""
        try:
            scan = db.session.get(Scan, scan_id)
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
                
            if scan.user_id != current_user.id:
                return jsonify({'error': 'Unauthorized'}), 403
                
            response = {
                'status': scan.status,
                'progress': scan.progress,
                'current_scanner': scan.current_scanner,
                'scan_status': scan.metrics.get('scan_status', {}) if scan.metrics else {}
            }
            
            if scan.status == 'completed':
                response['vulnerabilities'] = [result.to_dict() for result in scan.results]
            elif scan.status == 'error':
                response['error'] = scan.error_message
                
            return jsonify(response)
            
        except Exception as e:
            logger.error(f"Error getting scan status: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/status/<scan_id>')
    @login_required
    def get_status(scan_id):
        """Get the status of a running scan"""
        try:
            scan = Scan.query.get_or_404(scan_id)
            
            # Check if user owns this scan
            if scan.user_id != current_user.id:
                return jsonify({'error': 'Unauthorized'}), 403
                
            # Get vulnerabilities for this scan
            vulnerabilities = []
            for result in scan.results:
                try:
                    evidence = json.loads(result.evidence) if result.evidence else {}
                except json.JSONDecodeError:
                    evidence = {'error': 'Invalid evidence format'}
                    
                vulnerabilities.append({
                    'type': result.vulnerability_type,
                    'severity': result.severity,
                    'description': result.description,
                    'evidence': evidence
                })
                
            return jsonify({
                'status': scan.status,
                'progress': scan.progress,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'error': scan.error_message,
                'vulnerabilities': vulnerabilities,
                'current_scanner': scan.current_scanner
            })
            
        except Exception as e:
            logger.error(f"Error getting scan status: {str(e)}")
            return jsonify({'error': 'Failed to get scan status'}), 500

    @app.route('/scan/<int:scan_id>/details')
    @login_required
    def get_scan_details(scan_id):
        """Get detailed information about a specific scan"""
        try:
            scan = db.session.get(Scan, scan_id)
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
                
            if scan.user_id != current_user.id:
                return jsonify({'error': 'Unauthorized'}), 403
                
            return jsonify(scan.to_dict())
            
        except Exception as e:
            logger.error(f"Error getting scan details: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/scan/<int:scan_id>/report')
    @login_required
    def download_scan_report(scan_id):
        """Generate and download a PDF report for a scan"""
        try:
            scan = db.session.get(Scan, scan_id)
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
                
            if scan.user_id != current_user.id:
                return jsonify({'error': 'Unauthorized'}), 403
                
            # Generate PDF report
            pdf = FPDF()
            pdf.add_page()
            
            # Title
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'Vulnerability Scan Report', 0, 1, 'C')
            
            # Scan Information
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Scan Information', 0, 1, 'L')
            pdf.set_font('Arial', '', 12)
            pdf.cell(0, 10, f'Target URL: {scan.url}', 0, 1, 'L')
            pdf.cell(0, 10, f'Status: {scan.status}', 0, 1, 'L')
            pdf.cell(0, 10, f'Start Time: {scan.start_time.strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'L')
            if scan.completed_at:
                pdf.cell(0, 10, f'End Time: {scan.completed_at.strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'L')
                
            # Vulnerabilities
            pdf.add_page()
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, 'Vulnerabilities Found', 0, 1, 'L')
            
            if scan.results:
                if isinstance(scan.results, str):
                    try:
                        results = json.loads(scan.results)
                    except:
                        results = {'vulnerabilities': []}
                else:
                    results = scan.results
                    
                vulnerabilities = results.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    pdf.set_font('Arial', 'B', 11)
                    pdf.cell(0, 10, f"Type: {vuln.get('type', 'Unknown')}", 0, 1, 'L')
                    pdf.set_font('Arial', '', 11)
                    pdf.cell(0, 10, f"Severity: {vuln.get('severity', 'Unknown')}", 0, 1, 'L')
                    pdf.multi_cell(0, 10, f"Description: {vuln.get('description', 'No description')}", 0, 'L')
                    if vuln.get('evidence'):
                        pdf.multi_cell(0, 10, f"Evidence: {json.dumps(vuln['evidence'], indent=2)}", 0, 'L')
                    pdf.cell(0, 5, '', 0, 1, 'L')  # Add some space
            
            # Generate PDF
            response = make_response(pdf.output(dest='S').encode('latin1'))
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{scan_id}.pdf'
            return response
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return jsonify({'error': 'Error generating report'}), 500

    @app.route('/reports')
    @login_required
    def reports():
        """Show scan reports for the current user"""
        try:
            scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.start_time.desc()).all()
            return render_template('scan_reports.html', scans=scans)
        except Exception as e:
            logger.error(f"Error fetching reports: {str(e)}")
            flash('Error loading reports')
            return redirect(url_for('index'))

    @app.route('/scan/<int:scan_id>')
    @login_required
    def get_scan(scan_id):
        """Get detailed information about a specific scan"""
        try:
            scan = db.session.get(Scan, scan_id)
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
                
            if scan.user_id != current_user.id:
                return jsonify({'error': 'Unauthorized'}), 403
                
            # Prepare scan details
            details = {
                'id': scan.id,
                'target_url': scan.url,
                'status': scan.status,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.completed_at.isoformat() if scan.completed_at else None,
                'vulnerabilities': []
            }
            
            # Add vulnerabilities if scan is completed
            if scan.status == 'completed' and scan.results:
                if isinstance(scan.results, str):
                    try:
                        results = json.loads(scan.results)
                    except:
                        results = {'vulnerabilities': []}
                else:
                    results = scan.results
                    
                details['vulnerabilities'] = results.get('vulnerabilities', [])
                
            return jsonify(details)
            
        except Exception as e:
            logger.error(f"Error getting scan details: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.')
        return redirect(url_for('login'))

    @app.template_filter('datetime')
    def format_datetime(value):
        """Format a datetime object to a readable string"""
        if value is None:
            return ""
        return value.strftime('%Y-%m-%d %H:%M:%S')

    return app

# Create the application instance
app = create_app()

def run_scan_in_background(scan_id, url, checks):
    """Run the vulnerability scan in a background thread"""
    app = create_app()
    
    with app.app_context():
        try:
            scan = db.session.get(Scan, scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return
                
            scan.status = 'running'
            db.session.commit()
            
            # Create and run scanner
            scanner = VulnerabilityScanner(url)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Run the scan
                results = loop.run_until_complete(scanner.scan(checks))
                
                # Update scan record with results
                scan.end_time = dt.now(timezone.utc)
                scan.status = results.get('status', 'completed')
                scan.metrics = results.get('metrics', {})
                
                # Add vulnerability findings
                for vuln in results.get('vulnerabilities', []):
                    # Check if the table exists, create it if it doesn't
                    inspector = db.inspect(db.engine)
                    if not inspector.has_table('scan_result'):
                        db.create_all()
                        
                    result = ScanResult(
                        scan_id=scan.id,
                        vulnerability_type=vuln['type'],
                        severity=vuln['severity'],
                        description=vuln['description'],
                        evidence=vuln['evidence'],  # Evidence is already serialized to JSON
                        reproduction_steps=vuln['reproduction_steps'],  # Steps are already serialized
                        timestamp=dt.fromisoformat(vuln['timestamp'])
                    )
                    db.session.add(result)
                
                db.session.commit()
                
            except Exception as e:
                logger.error(f"Scan error: {str(e)}")
                scan.status = 'error'
                scan.error_message = str(e)
                scan.end_time = dt.now(timezone.utc)
                db.session.commit()
                
            finally:
                loop.close()
                
        except Exception as e:
            logger.error(f"Background scan error: {str(e)}")
            try:
                scan.status = 'error'
                scan.error_message = str(e)
                scan.end_time = dt.now(timezone.utc)
                db.session.commit()
            except Exception as commit_error:
                logger.error(f"Error updating scan status: {str(commit_error)}")

if __name__ == '__main__':
    app.run(debug=True)