#!/usr/bin/env python3
"""
Script to check if a folder contains any of the affected packages from packages.txt
Provides better performance and more detailed reporting than the bash version.

Usage:
    python3 check-affected-packages.py [directory]
    python3 check-affected-packages.py --json [directory]  # Output as JSON
"""

import re
import os
import sys
import json
from pathlib import Path
from collections import defaultdict
from typing import Set, Dict, List, Tuple


# ANSI color codes
class Colors:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    MAGENTA = "\033[0;35m"
    CYAN = "\033[0;36m"
    NC = "\033[0m"  # No Color


def extract_package_identifiers(packages_file: Path) -> Set[str]:
    """Extract unique package identifiers from packages.txt"""
    identifiers = set()

    with open(packages_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Extract package name (with or without scope)
            # Format: @scope/package@version or package@version
            if line.startswith("@"):
                # Scoped package: extract @scope/package part
                match = re.match(r"^(@[^/]+/[^@]+)", line)
                if match:
                    identifiers.add(match.group(1))
                else:
                    # Just the scope
                    match = re.match(r"^(@[^@/]+)", line)
                    if match:
                        identifiers.add(match.group(1))
            else:
                # Non-scoped package: extract package name before @
                match = re.match(r"^([^@]+)", line)
                if match:
                    identifiers.add(match.group(1))

    return identifiers


def find_lock_files(search_dir: Path) -> List[Path]:
    """Find all lock files in the directory"""
    lock_patterns = [
        "*lock*",
        "*.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "Gemfile.lock",
        "Cargo.lock",
        "poetry.lock",
    ]

    lock_files = []
    for pattern in lock_patterns:
        lock_files.extend(search_dir.rglob(pattern))

    # Remove duplicates and sort
    return sorted(set(f for f in lock_files if f.is_file()))


def search_in_file(
    file_path: Path, identifiers: Set[str]
) -> List[Tuple[int, str, str]]:
    """
    Search for package identifiers in a file
    Returns list of (line_number, line_content, matched_identifier)
    """
    matches = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for identifier in identifiers:
                    # Escape special regex characters
                    escaped = re.escape(identifier)
                    # Look for the identifier with word boundaries
                    if re.search(rf"\b{escaped}\b", line):
                        matches.append((line_num, line.strip(), identifier))
                        break  # Only count each line once
    except Exception as e:
        print(f"{Colors.RED}Error reading {file_path}: {e}{Colors.NC}", file=sys.stderr)

    return matches


def main():
    # Parse arguments
    output_json = "--json" in sys.argv
    if output_json:
        sys.argv.remove("--json")

    search_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    script_dir = Path(__file__).parent
    packages_file = script_dir / "packages.txt"

    # Check if packages.txt exists
    if not packages_file.exists():
        print(
            f"{Colors.RED}Error: packages.txt not found at {packages_file}{Colors.NC}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Check if search directory exists
    if not search_dir.exists():
        print(
            f"{Colors.RED}Error: Directory {search_dir} does not exist{Colors.NC}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not output_json:
        print(f"{Colors.BLUE}=== Affected Package Checker ==={Colors.NC}")
        print(f"Packages file: {Colors.YELLOW}{packages_file}{Colors.NC}")
        print(f"Search directory: {Colors.YELLOW}{search_dir}{Colors.NC}")
        print()

    # Extract package identifiers
    if not output_json:
        print(f"{Colors.BLUE}Extracting package identifiers...{Colors.NC}")

    identifiers = extract_package_identifiers(packages_file)

    if not output_json:
        print(
            f"{Colors.GREEN}Found {len(identifiers)} unique package identifiers{Colors.NC}"
        )
        print()

    # Find lock files
    if not output_json:
        print(f"{Colors.BLUE}Finding lock files...{Colors.NC}")

    lock_files = find_lock_files(search_dir)

    if not lock_files:
        if output_json:
            print(
                json.dumps(
                    {"status": "no_lock_files", "message": "No lock files found"}
                )
            )
        else:
            print(f"{Colors.YELLOW}No lock files found in {search_dir}{Colors.NC}")
        sys.exit(0)

    if not output_json:
        print(f"{Colors.GREEN}Found {len(lock_files)} lock file(s){Colors.NC}")
        print()
        print(f"{Colors.BLUE}Searching for affected packages...{Colors.NC}")
        print()

    # Search for matches
    results = defaultdict(list)
    matched_identifiers = set()

    for lock_file in lock_files:
        matches = search_in_file(lock_file, identifiers)
        if matches:
            results[lock_file] = matches
            matched_identifiers.update(m[2] for m in matches)

    # Output results
    if output_json:
        json_results = {
            "status": "affected" if results else "clean",
            "total_packages": len(identifiers),
            "total_lock_files": len(lock_files),
            "affected_files": len(results),
            "total_matches": sum(len(matches) for matches in results.values()),
            "matched_packages": sorted(matched_identifiers),
            "files": {
                str(file_path): [
                    {"line": line_num, "content": content, "package": pkg}
                    for line_num, content, pkg in matches
                ]
                for file_path, matches in results.items()
            },
        }
        print(json.dumps(json_results, indent=2))
    else:
        if not results:
            print(f"{Colors.GREEN}✓ No affected packages found{Colors.NC}")
            sys.exit(0)
        else:
            print(f"{Colors.RED}✗ Found affected packages:{Colors.NC}")
            print()

            for file_path, matches in results.items():
                print(f"{Colors.CYAN}File: {file_path}{Colors.NC}")

                # Group by package
                by_package = defaultdict(list)
                for line_num, content, pkg in matches:
                    by_package[pkg].append((line_num, content))

                for pkg, lines in by_package.items():
                    print(f"  {Colors.MAGENTA}Package: {pkg}{Colors.NC}")
                    for line_num, content in lines[:3]:  # Show first 3 matches
                        preview = content[:80] + "..." if len(content) > 80 else content
                        print(
                            f"    {Colors.YELLOW}Line {line_num}:{Colors.NC} {preview}"
                        )

                    if len(lines) > 3:
                        print(
                            f"    {Colors.YELLOW}... and {len(lines) - 3} more match(es){Colors.NC}"
                        )
                print()

            # Summary
            total_matches = sum(len(matches) for matches in results.values())
            print(f"{Colors.BLUE}=== Summary ==={Colors.NC}")
            print(
                f"Affected packages: {Colors.RED}{len(matched_identifiers)}{Colors.NC}"
            )
            print(f"Affected files: {Colors.RED}{len(results)}{Colors.NC}")
            print(f"Total matches: {Colors.RED}{total_matches}{Colors.NC}")
            print()
            print(f"{Colors.MAGENTA}Matched packages:{Colors.NC}")
            for pkg in sorted(matched_identifiers):
                print(f"  - {pkg}")

            sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.NC}")
        sys.exit(130)
