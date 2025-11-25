# Affected Package Checker

Scripts to detect if affected packages from the SHA-1 supply chain compromise are present in your project's lock files.

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

The scripts search for packages in various lock files:

- `package-lock.json` (npm)
- `yarn.lock` (Yarn)
- `pnpm-lock.yaml` (pnpm)
- `composer.lock` (PHP/Composer)
- `Gemfile.lock` (Ruby)
- `Cargo.lock` (Rust)
- `poetry.lock` (Python)
- Any file matching `*lock*` pattern

## Understanding the Output

### Bash Version Output

```
=== Affected Package Checker ===
Packages file: /path/to/packages.txt
Search directory: /path/to/project

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

### Python Version Output

```
=== Affected Package Checker ===
Packages file: /path/to/packages.txt
Search directory: /path/to/project

Extracting package identifiers...
Found 500 unique package identifiers

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
