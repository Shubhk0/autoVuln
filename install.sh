#!/bin/bash

# Exit on error
set -e

echo "Setting up virtual environment..."
# Create and activate virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Installing Playwright..."
playwright install

echo "Creating necessary directories..."
mkdir -p logs results reports instance

echo "Initializing database..."
python init_db.py

echo "Installation complete! You can now run the application with:"
echo "python app.py"