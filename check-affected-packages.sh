#!/usr/bin/env bash

# Script to check if a folder contains any of the affected packages from packages.txt
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
# This handles both scoped packages (@scope/package) and non-scoped packages
echo -e "${BLUE}Extracting package identifiers...${NC}"

# Create a regex pattern from the packages
# For scoped packages like @asyncapi/parser@1.0.0, we extract @asyncapi
# For non-scoped packages like lodash@1.0.0, we extract lodash
SCOPES=$(grep -oE '^(@[^/]+|[^@]+)' "$PACKAGES_FILE" | sort -u)

# Build regex pattern
# Group scoped packages together
SCOPED_PATTERN=$(echo "$SCOPES" | grep '^@' | sed 's/@/\\@/g' | paste -sd '|' -)
NONSCOPED_PATTERN=$(echo "$SCOPES" | grep -v '^@' | sed 's/\./\\./g' | paste -sd '|' -)

# Combine patterns
if [[ -n "$SCOPED_PATTERN" && -n "$NONSCOPED_PATTERN" ]]; then
    PATTERN="($SCOPED_PATTERN|$NONSCOPED_PATTERN)"
elif [[ -n "$SCOPED_PATTERN" ]]; then
    PATTERN="($SCOPED_PATTERN)"
else
    PATTERN="($NONSCOPED_PATTERN)"
fi

UNIQUE_COUNT=$(echo "$SCOPES" | wc -l | xargs)
echo -e "${GREEN}Found $UNIQUE_COUNT unique package identifiers${NC}"
echo ""

# Search for packages in lock files
echo -e "${BLUE}Searching for affected packages in lock files...${NC}"
echo ""

# Find all lock files first
LOCK_FILES=$(find "$SEARCH_DIR" -type f \( -name "*lock*" -o -name "*.lock" \) 2>/dev/null)

if [[ -z "$LOCK_FILES" ]]; then
    echo -e "${YELLOW}No lock files found in $SEARCH_DIR${NC}"
    exit 0
fi

LOCK_FILE_COUNT=$(echo "$LOCK_FILES" | wc -l | xargs)
echo -e "${GREEN}Found $LOCK_FILE_COUNT lock file(s)${NC}"
echo ""

# Search for matches
MATCHES=$(grep -rE --include='*lock*' --include='*.lock' "$PATTERN" "$SEARCH_DIR" 2>/dev/null || true)

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
