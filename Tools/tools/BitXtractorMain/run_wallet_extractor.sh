#!/bin/bash
#BitXTractor.sh
# Wrapper script to run the BitXTractor, tests, or GUI
# Usage: ./run_BitXTractor.sh [--test] [--gui] [--wallet <path>] [--passphrase <pass>]

# Default values
WALLET_PATH="wallet.dat"
PASSPHRASE="mysecretpassphrase"
RUN_TESTS=0
RUN_GUI=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --test)
            RUN_TESTS=1
            shift
            ;;
        --gui)
            RUN_GUI=1
            shift
            ;;
        --wallet)
            WALLET_PATH="$2"
            shift 2
            ;;
        --passphrase)
            PASSPHRASE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Set watermark
export R3AL3R_USER_HASH=$(echo -n "${USER:-${USERNAME:-unknown}}" | sha256sum | cut -d' ' -f1)

# Check for dependencies
for dep in python3 pip3; do
    if ! command -v $dep &> /dev/null; then
        echo "Error: $dep is required"
        exit 1
    fi
done

# Install dependencies if not present
pip3 show bsddb3 >/dev/null 2>&1 || pip3 install bsddb3
pip3 show cryptography >/dev/null 2>&1 || pip3 install cryptography
pip3 show base58 >/dev/null 2>&1 || pip3 install base58
pip3 show pytest >/dev/null 2>&1 || pip3 install pytest

# Ensure dictionaries folder exists
mkdir -p dictionaries

# Run main script, tests, or GUI
if [ $RUN_TESTS -eq 1 ]; then
    echo "Running tests..."
    pytest tests/test_BitXTractor.py -v --log-file=pytest.log
elif [ $RUN_GUI -eq 1 ]; then
    echo "Running BitXTractor with GUI..."
    python3 BitXTractor.py --gui
else
    echo "Running BitXTractor..."
    python3 BitXTractor.py --wallet "$WALLET_PATH" --passphrase "$PASSPHRASE"
fi