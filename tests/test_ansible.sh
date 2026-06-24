#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "======================================"
echo "Running Ansible Tests..."
echo "======================================"

cd "$(dirname "$0")/.."

echo -e "${GREEN}[1/2] Running Ansible Lint...${NC}"
# We ignore some warnings that are common and might not be critical for this setup
ansible-lint ansible/playbook.yml || { echo -e "${RED}Ansible Lint failed!${NC}"; exit 1; }

echo -e "\n${GREEN}[2/2] Running Ansible Syntax Check...${NC}"
ansible-playbook -i ansible/inventory.yml ansible/playbook.yml --syntax-check || { echo -e "${RED}Syntax check failed!${NC}"; exit 1; }

echo -e "\n${GREEN}All Ansible tests passed successfully!${NC}"
