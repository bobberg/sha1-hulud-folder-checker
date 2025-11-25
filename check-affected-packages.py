#!/usr/bin/env python3
"""
Script to check if a folder contains any of the affected packages from packages.txt
Optimized version with compiled regex and parallel processing.

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
from typing import Set, Dict, List, Tuple, Pattern
from concurrent.futures import ThreadPoolExecutor, as_completed


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
    """Find all lock files in the directory, excluding common ignore patterns"""
    # Specific lock file names to search for
    specific_files = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "Gemfile.lock",
        "Cargo.lock",
        "poetry.lock",
        "Pipfile.lock",
        "go.sum",
        "packages.lock.json",
    ]

    # Directories to skip
    skip_dirs = {
        "node_modules",
        ".git",
        ".svn",
        ".hg",
        "vendor",
        "venv",
        ".venv",
        "env",
        ".env",
        "__pycache__",
        "dist",
        "build",
        ".cache",
        ".tox",
        "target",
    }

    lock_files = []

    # Walk the directory tree manually to skip unwanted directories
    for root, dirs, files in os.walk(search_dir):
        # Remove skip directories from dirs list (modifies in-place)
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for filename in files:
            if filename in specific_files:
                file_path = Path(root) / filename
                # Skip files larger than 50MB (likely not real lock files)
                try:
                    if file_path.stat().st_size < 50 * 1024 * 1024:
                        lock_files.append(file_path)
                except OSError:
                    pass

    return sorted(lock_files)


def build_combined_regex(identifiers: Set[str]) -> Pattern:
    """Build a single compiled regex pattern from all identifiers"""
    # Sort by length (longest first) to match more specific patterns first
    sorted_identifiers = sorted(identifiers, key=len, reverse=True)

    # Escape special regex characters and build pattern
    escaped = [re.escape(ident) for ident in sorted_identifiers]

    # Use non-capturing groups and word boundaries
    pattern = r"\b(?:" + "|".join(escaped) + r")\b"

    return re.compile(pattern)


def check_for_iocs(search_dir: Path) -> Dict[str, List[Path]]:
    """Check for indicators of compromise (IoCs) related to the SHA-1 attack"""
    iocs_found = defaultdict(list)
    
    # Malicious files to look for (use set for O(1) lookup)
    malicious_files = {'bun_environment.js', 'trufflehog', 'trufflehog.exe'}
    
    # Skip directories (combined with lock file search skip_dirs)
    skip_dirs = {
        'node_modules', '.git', '.svn', '.hg', 'vendor', 
        'venv', '.venv', 'env', '.env', '__pycache__',
        'dist', 'build', '.cache', '.tox', 'target'
    }
    
    # Check for malicious files and directories
    for root, dirs, files in os.walk(search_dir):
        # Filter out skip directories in-place for efficiency
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        root_path = Path(root)
        root_str = str(root_path)
        
        # Quick check for .truffler-cache directory
        if '.truffler-cache' in root_str:
            iocs_found['malicious_directory'].append(root_path)
        
        # Check files only if any exist
        if not files:
            continue
            
        # Use set intersection for fast file matching
        found_files = malicious_files.intersection(files)
        for filename in found_files:
            file_path = root_path / filename
            
            # Categorize by type
            if filename == 'bun_environment.js':
                if 'node_modules' in root_str:
                    iocs_found['post_install_script'].append(file_path)
                else:
                    iocs_found['malicious_file'].append(file_path)
            else:
                iocs_found['malicious_file'].append(file_path)
    
    # Check home directory for .truffler-cache (fast, single check)
    home_dir = Path.home()
    truffler_cache = home_dir / '.truffler-cache'
    if truffler_cache.exists():
        if truffler_cache not in iocs_found['malicious_directory']:
            iocs_found['malicious_directory'].append(truffler_cache)
        
        # Check for binaries using glob (faster than individual exists checks)
        for binary_path in truffler_cache.glob('trufflehog*'):
            if binary_path.is_file():
                iocs_found['malicious_binary'].append(binary_path)
    
    return dict(iocs_found)


def search_in_file(
    file_path: Path, pattern: Pattern, identifiers: Set[str]
) -> List[Tuple[int, str, str]]:
    """
    Search for package identifiers in a file using compiled regex
    Returns list of (line_number, line_content, matched_identifier)
    """
    matches = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                # Use the compiled pattern for fast searching
                match = pattern.search(line)
                if match:
                    matched_text = match.group(0)
                    matches.append((line_num, line.strip(), matched_text))
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
    
    # Check for IoCs first
    if not output_json:
        print(f"{Colors.BLUE}Checking for indicators of compromise (IoCs)...{Colors.NC}")
    
    iocs = check_for_iocs(search_dir)
    
    if iocs and not output_json:
        print(f"{Colors.RED}⚠ WARNING: Found indicators of compromise!{Colors.NC}")
        for ioc_type, paths in iocs.items():
            print(f"  {Colors.MAGENTA}{ioc_type}:{Colors.NC}")
            for path in paths:
                print(f"    {Colors.RED}✗ {path}{Colors.NC}")
        print()
    elif not output_json:
        print(f"{Colors.GREEN}✓ No IoCs detected{Colors.NC}")
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

    # Build compiled regex pattern for fast searching
    if not output_json:
        print(f"{Colors.BLUE}Building search pattern...{Colors.NC}")

    pattern = build_combined_regex(identifiers)

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

    # Search for matches using parallel processing
    results = defaultdict(list)
    matched_identifiers = set()

    # Use ThreadPoolExecutor for parallel file processing
    max_workers = min(10, len(lock_files))  # Cap at 10 threads

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all file searches
        future_to_file = {
            executor.submit(search_in_file, lock_file, pattern, identifiers): lock_file
            for lock_file in lock_files
        }

        # Collect results as they complete
        for future in as_completed(future_to_file):
            lock_file = future_to_file[future]
            try:
                matches = future.result()
                if matches:
                    results[lock_file] = matches
                    matched_identifiers.update(m[2] for m in matches)
            except Exception as e:
                print(
                    f"{Colors.RED}Error processing {lock_file}: {e}{Colors.NC}",
                    file=sys.stderr,
                )

    # Output results
    if output_json:
        json_results = {
            "status": "affected" if results else "clean",
            "total_packages": len(identifiers),
            "total_lock_files": len(lock_files),
            "affected_files": len(results),
            "total_matches": sum(len(matches) for matches in results.values()),
            "matched_packages": sorted(matched_identifiers),
            "iocs": {
                ioc_type: [str(p) for p in paths]
                for ioc_type, paths in iocs.items()
            } if iocs else {},
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
            if iocs:
                total_iocs = sum(len(paths) for paths in iocs.values())
                print(f"IoCs found: {Colors.RED}{total_iocs}{Colors.NC}")
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
