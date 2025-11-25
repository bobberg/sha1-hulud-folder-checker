#!/usr/bin/env bash

# Script to check if a folder contains any of the affected packages from packages.txt
# Optimized version with proper lock file detection and exclusions
# Usage: ./check-affected-packages.sh [directory]
# If no directory is provided, it searches the current directory

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGES_FILE="${SCRIPT_DIR}/packages.txt"
SEARCH_DIR="${1:-.}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if packages.txt exists
if [[ ! -f "$PACKAGES_FILE" ]]; then
    echo -e "${RED}Error: packages.txt not found at $PACKAGES_FILE${NC}"
    exit 1
fi

# Check if search directory exists
if [[ ! -d "$SEARCH_DIR" ]]; then
    echo -e "${RED}Error: Directory $SEARCH_DIR does not exist${NC}"
    exit 1
fi

echo -e "${BLUE}=== Affected Package Checker ===${NC}"
echo -e "Packages file: ${YELLOW}$PACKAGES_FILE${NC}"
echo -e "Search directory: ${YELLOW}$SEARCH_DIR${NC}"
echo ""

# Extract unique package scopes/names from packages.txt
echo -e "${BLUE}Extracting package identifiers...${NC}"

# Extract package names/scopes and build pattern
# For @scope/package@version, extract full package name @scope/package
IDENTIFIERS=$(awk -F'@' '
    /^@/ { 
        # Scoped package: extract @scope/package
        if (match($0, /^@[^@]+/)) {
            print substr($0, RSTART, RLENGTH)
        }
    }
    /^[^@]/ { 
        # Non-scoped: extract package name
        print $1
    }
' "$PACKAGES_FILE" | sort -u)

# Build grep pattern with proper escaping
PATTERN=$(echo "$IDENTIFIERS" | sed 's/[.[\*^$()+?{|]/\\&/g' | paste -sd '|' -)

UNIQUE_COUNT=$(echo "$IDENTIFIERS" | wc -l | xargs)
echo -e "${GREEN}Found $UNIQUE_COUNT unique package identifiers${NC}"
echo ""

# Search for packages in lock files
echo -e "${BLUE}Finding lock files...${NC}"

# Find specific lock files, excluding common directories
LOCK_FILES=$(find "$SEARCH_DIR" -type f \( \
    -name "package-lock.json" -o \
    -name "yarn.lock" -o \
    -name "pnpm-lock.yaml" -o \
    -name "composer.lock" -o \
    -name "Gemfile.lock" -o \
    -name "Cargo.lock" -o \
    -name "poetry.lock" -o \
    -name "Pipfile.lock" -o \
    -name "go.sum" -o \
    -name "packages.lock.json" \
\) -not -path "*/node_modules/*" \
   -not -path "*/.git/*" \
   -not -path "*/vendor/*" \
   -not -path "*/venv/*" \
   -not -path "*/.venv/*" \
   -not -path "*/dist/*" \
   -not -path "*/build/*" \
   -not -path "*/target/*" \
   2>/dev/null || true)

if [[ -z "$LOCK_FILES" ]]; then
    echo -e "${YELLOW}No lock files found in $SEARCH_DIR${NC}"
    exit 0
fi

LOCK_FILE_COUNT=$(echo "$LOCK_FILES" | wc -l | xargs)
echo -e "${GREEN}Found $LOCK_FILE_COUNT lock file(s)${NC}"
echo ""

echo -e "${BLUE}Searching for affected packages...${NC}"
echo ""

# Search for matches using the list of files
MATCHES=$(echo "$LOCK_FILES" | xargs grep -E "$PATTERN" 2>/dev/null || true)

if [[ -z "$MATCHES" ]]; then
    echo -e "${GREEN}✓ No affected packages found${NC}"
    exit 0
else
    echo -e "${RED}✗ Found affected packages:${NC}"
    echo ""
    echo "$MATCHES" | while IFS=: read -r file match; do
        echo -e "${YELLOW}File:${NC} $file"
        echo -e "${RED}Match:${NC} $match"
        echo ""
    done
    
    # Summary
    MATCH_COUNT=$(echo "$MATCHES" | wc -l | xargs)
    AFFECTED_FILES=$(echo "$MATCHES" | cut -d: -f1 | sort -u | wc -l | xargs)
    
    echo -e "${BLUE}=== Summary ===${NC}"
    echo -e "Total matches: ${RED}$MATCH_COUNT${NC}"
    echo -e "Affected files: ${RED}$AFFECTED_FILES${NC}"
    
    exit 1
fi
