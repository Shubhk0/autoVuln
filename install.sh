#!/bin/bash

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Install playwright separately and install browsers
pip install playwright
playwright install

# Additional setup steps...

echo "Installation complete!" 