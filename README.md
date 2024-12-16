# Web Vulnerability Scanner

An asynchronous web application security scanner written in Python.

## Features

- XSS (Cross-Site Scripting) Detection
- SQL Injection Detection
- CSRF (Cross-Site Request Forgery) Detection
- Security Headers Analysis
- SSL/TLS Configuration Checks
- Rate Limiting
- Concurrent Scanning
- Result Prioritization

## Installation

1. Clone the repository:

```
git clone https://github.com/Shubhk0/autoVuln.git
cd autoVuln
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install Playwright:
```bash
pip install playwright
playwright install
```

5. Run the scanner:
```bash
python vulnscan.py --url https://example.com
```
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
git clone https://github.com/Shubhk0/autoVuln.git
cd autoVuln
```
2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install playwright:
```bash
pip install playwright
playwright install
```

5. Run the scanner:
```bash
python vulnscan.py --url https://example.com
```
```

4. Make sure your `.gitignore` has these entries at the top:
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
```

Playwright specific
/playwright/driver/
node_modules/
playwright-downloads/
/driver/node
/driver/package/


5. Clean up requirements.txt to remove any development dependencies:
```text:requirements.txt
# Core dependencies
aiohttp>=3.8.0
beautifulsoup4>=4.9.3
colorama>=0.4.4
psutil>=5.8.0
urllib3>=1.26.7
python-dotenv>=0.19.0
pydantic>=1.9.0
```

Optional: Only if using Playwright
playwright>=1.20.0 # Install separately via install.sh
6. Update install.sh to create necessary directories:
bash:install.sh
#!/bin/bash

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate

# Create necessary directories
mkdir -p logs results reports
```
# Install requirements
```bash
pip install -r requirements.txt
```
# Install playwright separately and install browsers
```bash
pip install playwright
playwright install
```
# echo "Installation complete!"
```

7. Now try pushing again:
```bash
git add .
git commit -m "Clean repository setup"
git push -f origin main
```
