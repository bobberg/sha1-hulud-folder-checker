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

# Extract unique package scopes/names from packages.txt (do this early, doesn't require filesystem scan)
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

# Single find pass for BOTH IoCs and lock files (major performance boost)
echo -e "${BLUE}Scanning filesystem (IoCs + lock files)...${NC}"

# Find everything in one pass - IoC files, IoC dirs, and lock files
ALL_RESULTS=$(find "$SEARCH_DIR" \( \
    -type f \( \
        -name "bun_environment.js" -o \
        -name "trufflehog" -o \
        -name "trufflehog.exe" -o \
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
    \) -o \
    -type d -name ".truffler-cache" \
\) -not -path '*/node_modules/*' \
   -not -path '*/.git/*' \
   -not -path '*/vendor/*' \
   -not -path '*/venv/*' \
   -not -path '*/.venv/*' \
   -not -path '*/dist/*' \
   -not -path '*/build/*' \
   -not -path '*/target/*' \
   2>/dev/null || true)

# Separate IoC files, IoC dirs, and lock files using grep
IOC_FILES=$(echo "$ALL_RESULTS" | grep -E '(bun_environment\.js|trufflehog(\.exe)?)$' || true)
IOC_DIRS=$(echo "$ALL_RESULTS" | grep -E '\.truffler-cache$' || true)
LOCK_FILES=$(echo "$ALL_RESULTS" | grep -E '(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|Cargo\.lock|poetry\.lock|Pipfile\.lock|go\.sum|packages\.lock\.json)$' || true)

# Check home directory for .truffler-cache (quick, no full scan)
HOME_CACHE="$HOME/.truffler-cache"
if [[ -d "$HOME_CACHE" ]]; then
    IOC_DIRS="${IOC_DIRS}${IOC_DIRS:+$'\n'}${HOME_CACHE}"
fi

# Report IoCs
IOCS_FOUND=false
if [[ -n "$IOC_FILES" ]] || [[ -n "$IOC_DIRS" ]]; then
    IOCS_FOUND=true
    echo -e "${RED}⚠ WARNING: Found indicators of compromise!${NC}"
    
    if [[ -n "$IOC_FILES" ]]; then
        echo -e "  ${YELLOW}Malicious files:${NC}"
        echo "$IOC_FILES" | while read -r file; do
            echo -e "    ${RED}✗ $file${NC}"
        done
    fi
    
    if [[ -n "$IOC_DIRS" ]]; then
        echo -e "  ${YELLOW}Malicious directories:${NC}"
        echo "$IOC_DIRS" | while read -r dir; do
            echo -e "    ${RED}✗ $dir${NC}"
        done
    fi
    echo ""
else
    echo -e "${GREEN}✓ No IoCs detected${NC}"
    echo ""
fi

# Report lock files found

# Report lock files found
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
    
    # Add IoC count if any were found
    if [[ "$IOCS_FOUND" == true ]]; then
        IOC_COUNT=0
        [[ -n "$IOC_FILES" ]] && IOC_COUNT=$((IOC_COUNT + $(echo "$IOC_FILES" | wc -l | xargs)))
        [[ -n "$IOC_DIRS" ]] && IOC_COUNT=$((IOC_COUNT + $(echo "$IOC_DIRS" | wc -l | xargs)))
        echo -e "IoCs found: ${RED}$IOC_COUNT${NC}"
    fi
    
    exit 1
fi
