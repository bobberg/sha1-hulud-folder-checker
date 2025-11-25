# Affected Package Checker

Scripts to detect if affected packages from the SHA-1 supply chain compromise are present in your project's lock files.

> **Note:** This checker currently contains the list of 1000+ affected packages identified as of November 25, 2025, based on the analysis from Semgrep's article: [Digging for Secrets: SHA1-Hulud, the Second Coming of the npm Worm](https://semgrep.dev/blog/2025/digging-for-secrets-sha1-hulud-the-second-coming-of-the-npm-worm/). The list may be updated as more affected packages are discovered.

## Overview

This repository contains two scripts that scan lock files for over 1000 packages affected by the SHA-1 supply chain attack:

- **Bash version** (`check-affected-packages.sh`) - Fast, portable, requires only bash
- **Python version** (`check-affected-packages.py`) - More detailed reporting, JSON output support

## Installation

### Prerequisites

**Bash version:**

- Bash 4.0+ (macOS users: built-in bash works fine)
- Standard Unix tools: grep, find, sort

**Python version:**

- Python 3.6+

### Setup

1. Clone or download this repository
2. Make scripts executable:
   ```bash
   chmod +x check-affected-packages.sh
   chmod +x check-affected-packages.py
   ```

## Usage

### Bash Version

Check current directory:

```bash
./check-affected-packages.sh
```

Check specific directory:

```bash
./check-affected-packages.sh /path/to/your/project
```

### Python Version

Check current directory:

```bash
python3 check-affected-packages.py
```

Check specific directory:

```bash
python3 check-affected-packages.py /path/to/your/project
```

Get JSON output for automation:

```bash
python3 check-affected-packages.py --json /path/to/your/project
```

## What it Checks

### Lock Files

The scripts search for packages in various lock files:

- `package-lock.json` (npm)
- `yarn.lock` (Yarn)
- `pnpm-lock.yaml` (pnpm)
- `composer.lock` (PHP/Composer)
- `Gemfile.lock` (Ruby)
- `Cargo.lock` (Rust)
- `poetry.lock` (Python)
- `Pipfile.lock` (Python)
- `go.sum` (Go)
- `packages.lock.json` (NuGet)

### Indicators of Compromise (IoCs)

In addition to checking lock files, the scripts also detect active malware indicators:

**Malicious Files:**
- `bun_environment.js` - Post-install malware script
- `trufflehog` - Downloaded credential stealer binary (Linux/Mac)
- `trufflehog.exe` - Downloaded credential stealer binary (Windows)

**Malicious Directories:**
- `.truffler-cache/` - Hidden directory in project or home directory
- `.truffler-cache/extract/` - Temporary extraction directory

**Home Directory Check:**
- Automatically scans `~/.truffler-cache` for malware binaries

The scripts will show warnings if any IoCs are detected, indicating that the malware may have already executed on the system.

## Understanding the Output

### Bash Version Output

```
=== Affected Package Checker ===
Packages file: /path/to/packages.txt
Search directory: /path/to/project

Checking for indicators of compromise (IoCs)...
✓ No IoCs detected

Found 500 unique package identifiers

Searching for affected packages in lock files...

Found 2 lock file(s)

✗ Found affected packages:

File: ./package-lock.json
Match:     "@asyncapi/parser": "^1.0.0",

=== Summary ===
Total matches: 1
Affected files: 1
```

**With IoCs detected:**

```
Checking for indicators of compromise (IoCs)...
⚠ WARNING: Found indicators of compromise!
  Malicious files:
    ✗ /path/to/node_modules/.bin/bun_environment.js
  Malicious directories:
    ✗ /Users/username/.truffler-cache

=== Summary ===
Total matches: 1
Affected files: 1
IoCs found: 2
```

### Python Version Output

```
=== Affected Package Checker ===
Packages file: /path/to/packages.txt
Search directory: /path/to/project

Checking for indicators of compromise (IoCs)...
✓ No IoCs detected

Extracting package identifiers...
Found 500 unique package identifiers

Building search pattern...
Finding lock files...
Found 2 lock file(s)

Searching for affected packages...

✗ Found affected packages:

File: package-lock.json
  Package: @asyncapi/parser
    Line 42: "@asyncapi/parser": "^1.0.0",

=== Summary ===
Affected packages: 1
Affected files: 1
Total matches: 1

Matched packages:
  - @asyncapi/parser
```

### JSON Output (Python only)

```json
{
  "status": "affected",
  "total_packages": 500,
  "total_lock_files": 2,
  "affected_files": 1,
  "total_matches": 1,
  "matched_packages": ["@asyncapi/parser"],
  "iocs": {
    "malicious_file": ["/path/to/bun_environment.js"],
    "malicious_directory": ["/Users/username/.truffler-cache"]
  },
  "files": {
    "package-lock.json": [
      {
        "line": 42,
        "content": "\"@asyncapi/parser\": \"^1.0.0\",",
        "package": "@asyncapi/parser"
      }
    ]
  }
}
```

**Note:** The `iocs` field will be an empty object `{}` if no indicators of compromise are detected.

## Exit Codes

- `0` - No affected packages found (clean)
- `1` - Affected packages found (or error occurred)
- `130` - Interrupted by user (Ctrl+C)

## CI/CD Integration

### GitHub Actions

```yaml
name: Check Affected Packages

on: [push, pull_request]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run package checker
        run: |
          python3 check-affected-packages.py
        continue-on-error: false
```

### GitLab CI

```yaml
check_packages:
  script:
    - python3 check-affected-packages.py
  allow_failure: false
```

## Performance

- **Bash version**: Typically scans in 1-5 seconds for medium projects
- **Python version**: Typically scans in 2-10 seconds, provides more detailed analysis
- **IoC detection**: Adds minimal overhead (< 1 second) as it's optimized with single directory traversal

Both scripts automatically skip common bloat directories (node_modules, .git, vendor, etc.) for maximum efficiency.

## What To Do If IoCs Are Found

If the scripts detect indicators of compromise:

1. **Immediately disconnect** the affected system from the network
2. **Do not run** any package manager commands (npm, yarn, etc.)
3. **Check for credential theft**: The malware attempts to steal credentials using Trufflehog
4. **Review your secrets**: Check for unauthorized access to:
   - GitHub/GitLab tokens
   - AWS/Azure credentials
   - API keys
   - SSH keys
   - Environment variables
5. **Rotate all credentials** that may have been exposed
6. **Remove malicious files**:
   ```bash
   rm -rf ~/.truffler-cache
   rm -f **/bun_environment.js
   ```
7. **Clean reinstall**: Delete `node_modules` and reinstall from clean lock files
8. **Review process history**: Check for suspicious processes that may have run

**Note:** If IoCs are found, your system may have already been compromised. Take immediate action to secure your credentials and systems.

## Customization

### Adding More Packages

Edit `packages.txt` and add packages in the format:

```
@scope/package@version
package@version
```

The scripts will automatically extract package identifiers.

### Modifying Lock File Patterns

Edit the `lock_patterns` in the Python script or the `--include` pattern in the bash script to add more file patterns.

## Troubleshooting

**No lock files found:**

- Ensure you're running the script in or pointing to a directory with lock files
- Check if your lock files match the expected patterns

**Permission denied:**

- Make sure scripts are executable: `chmod +x check-affected-packages.sh`
- Check file permissions on the search directory

**Python script not working:**

- Verify Python 3 is installed: `python3 --version`
- Check that `packages.txt` is in the same directory as the script

## License

MIT

## Contributing

Feel free to submit issues or pull requests to improve these scripts!
