# Web Vulnerability Scanner

An asynchronous web application security scanner with web interface.

## Features

- XSS (Cross-Site Scripting) Detection
- SQL Injection Detection
- CSRF (Cross-Site Request Forgery) Detection
- Security Headers Analysis
- SSL/TLS Configuration Checks
- Rate Limiting
- Concurrent Scanning
- Result Prioritization
- Web Interface for Easy Management

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Shubhk0/autoVuln.git
cd autoVuln
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Run the installation script:
```bash
chmod +x install.sh
./install.sh
```

4. Start the web application:
```bash
python app.py
```

The application will be available at http://localhost:5000

## CLI Usage

You can also use the scanner from command line:

```bash
python vulnscan.py --url https://example.com
```

## Configuration

Create a `.env` file in the project root:

```env
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///instance/scanner.db
```

## Development

1. Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

2. Run tests:
```bash
pytest
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
```

## .gitignore

Make sure your `.gitignore` has these entries at the top:

```text:.gitignore
# Virtual Environment - IMPORTANT: NEVER COMMIT THESE
venv/
env/
ENV/
.venv/
.env
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.so

# Playwright specific
**/playwright/driver/
node_modules/
playwright-downloads/
**/driver/node
**/driver/package/
```

## requirements.txt

Clean up requirements.txt to remove any development dependencies:

```text:requirements.txt
# Core dependencies
aiohttp>=3.8.0
beautifulsoup4>=4.9.3
colorama>=0.4.4
psutil>=5.8.0
urllib3>=1.26.7
python-dotenv>=0.19.0
pydantic>=1.9.0

# Optional: Only if using Playwright
# playwright>=1.20.0  # Install separately via install.sh
```

## install.sh

Update install.sh to create necessary directories:

```bash:install.sh
#!/bin/bash

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Create necessary directories
mkdir -p logs results reports

# Install requirements
pip install -r requirements.txt

# Install playwright separately and install browsers
pip install playwright
playwright install

echo "Installation complete!"
```

## Pushing to Remote

Now try pushing again:

```bash
# Verify what will be committed
git status

# If everything looks clean (no venv directory)
git add .
git commit -m "Clean repository setup"
git push -f origin main
```
