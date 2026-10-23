#!/usr/bin/env bash
set -e

# ANSI Color Codes
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}${CYAN}   COMPLIANCE-AWARE BLOCK BUILDER & RELAY — TEST SUITE RUNNER            ${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}\n"

PASS_COUNT=0
FAIL_COUNT=0
FAILED_SUITES=()

run_suite() {
    local suite_name="$1"
    local dir="$2"
    local cmd="$3"

    echo -e "${BOLD}${BLUE}==> Running [${suite_name}]...${NC}"
    pushd "$dir" > /dev/null
    if eval "$cmd"; then
        echo -e "${GREEN}✓ [${suite_name}] PASSED${NC}\n"
        ((PASS_COUNT++))
    else
        echo -e "${RED}✗ [${suite_name}] FAILED${NC}\n"
        ((FAIL_COUNT++))
        FAILED_SUITES+=("$suite_name")
    fi
    popd > /dev/null
}

# 1. Foundry Solidity Smart Contract Tests
run_suite "Solidity Smart Contracts (Forge)" \
          "$ROOT_DIR/contracts" \
          "forge test --summary"

# 2. Rust Compliance Engine Tests
run_suite "Rust Compliance Engine (Cargo)" \
          "$ROOT_DIR/engine" \
          "cargo test"

# 3. Rust PBS Relay Tests
run_suite "Rust PBS Relay (Cargo)" \
          "$ROOT_DIR/relay" \
          "cargo test"

# 4. Fastify Orchestration API Tests
run_suite "Fastify API Orchestrator (Node.js)" \
          "$ROOT_DIR/api" \
          "npm test"

# 5. Regulatory AI Explainer Tests
run_suite "Regulatory AI Explainer (pytest)" \
          "$ROOT_DIR/ai-explainer" \
          "python3 -m pytest test_explainer.py -q"

# Summary Report
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}${CYAN}   TEST EXECUTION SUMMARY                                               ${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "Total Suites Run: $((PASS_COUNT + FAIL_COUNT))"
echo -e "${GREEN}Suites Passed:   ${PASS_COUNT}${NC}"

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}Suites Failed:   ${FAIL_COUNT}${NC}"
    echo -e "${RED}Failed Components: ${FAILED_SUITES[*]}${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL TEST SUITES PASSED CLEANLY (100% SUCCESS)${NC}"
    exit 0
fi
