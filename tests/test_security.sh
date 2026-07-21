#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "======================================"
echo "Running Security Audit..."
echo "======================================"

cd "$(dirname "$0")/.."

echo -e "${GREEN}Running pip-audit for Python dependency vulnerabilities...${NC}"
pip-audit || { echo -e "${RED}Security audit failed! Vulnerabilities found.${NC}"; exit 1; }

echo -e "\n${GREEN}All security checks passed successfully!${NC}"
