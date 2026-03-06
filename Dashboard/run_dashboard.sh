#!/bin/bash
# run_dashboard.sh

echo "ðŸš€ Starting AuthLog Security Dashboard..."
echo "========================================="

# Check if running as root (needed for reading auth logs)
if [ "$EUID" -ne 0 ]; then 
    echo "âš ï¸  Warning: Not running as root. You may not be able to read auth logs."
    echo "   Consider running with: sudo $0"
    echo ""
fi

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "âŒ Python3 not found. Please install Python 3.6+"
    exit 1
fi

# Check if requirements.txt exists
if [ ! -f "requirements.txt" ]; then
    echo "ðŸ“ Creating requirements.txt..."
    cat > requirements.txt << EOF
matplotlib>=3.5.0
numpy>=1.21.0
EOF
fi

# Install requirements if needed
if [ ! -d "venv" ]; then
    echo "ðŸ“¦ Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Run the dashboard
python3 auth_dashboard.py "$@"
