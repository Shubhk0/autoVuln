#!/bin/bash

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Create necessary directories
mkdir -p logs results reports

# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

# Install playwright separately and install browsers
pip install playwright
playwright install

# Create database directory if using SQLite
mkdir -p instance

echo "Installation complete!" 