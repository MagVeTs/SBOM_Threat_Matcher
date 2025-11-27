# SBOM Threat Matcher

A lightweight, standalone Python utility for scanning Software Bills of Materials (SBOMs) and lockfiles against a list of known malicious or disallowed packages.

Designed originally to detect the **Shai-Hulud 2.0** supply chain attack, this tool is generic and can be used to check for any set of package names (e.g., malware, typo-squatting lists, or blacklisted libraries).

## Features
* **Versatile Input:** Supports standard **SPDX** and **CycloneDX** SBOMs, as well as **GitHub Dependency Graph** exports.
* **Direct Lockfile Support:** Can scan raw `package-lock.json` files (v1, v2, and v3) directly, including deep/nested dependencies.
* **GitHub API Compatible:** Automatically "unwraps" JSON responses from the GitHub API (`dependency-graph/sbom`).
* **Flexible matching:** Matches package names regardless of version numbers in the source list.
* **Zero Dependencies:** Runs on standard Python 3 with no need to `pip install` anything.

## Prerequisites
* Python 3.6 or higher

## Setup
1. Save the script as `check_sbom.py` (or your preferred name).
2. Create a text file (default: `vulnerable_packages.txt`) containing the list of package names you want to flag.

## Usage

The script is run from the command line and accepts two arguments.

```bash
python3 check_sbom.py [TARGET_FILE] [THREAT_LIST]

* TARGET_FILE (Required): The JSON file you want to scan (SBOM or lockfile).
* THREAT_LIST (Optional): Path to the text file containing bad package names. If omitted, defaults to vulnerable_packages.txt in the current directory.

Here is the complete content formatted strictly as a Markdown file. You can copy the code block below directly into a file named README.md.

Markdown

# SBOM Threat Matcher

A lightweight, standalone Python utility for scanning Software Bills of Materials (SBOMs) and lockfiles against a list of known malicious or disallowed packages.

Designed originally to detect the **Shai-Hulud 2.0** supply chain attack, this tool is generic and can be used to check for any set of package names (e.g., malware, typo-squatting lists, or blacklisted libraries).

## Features
* **Versatile Input:** Supports standard **SPDX** and **CycloneDX** SBOMs, as well as **GitHub Dependency Graph** exports.
* **Direct Lockfile Support:** Can scan raw `package-lock.json` files (v1, v2, and v3) directly, including deep/nested dependencies.
* **GitHub API Compatible:** Automatically "unwraps" JSON responses from the GitHub API (`dependency-graph/sbom`).
* **Flexible matching:** Matches package names regardless of version numbers in the source list.
* **Zero Dependencies:** Runs on standard Python 3 with no need to `pip install` anything.

## Prerequisites
* Python 3.6 or higher

## Setup
1. Save the script as `check_sbom.py` (or your preferred name).
2. Create a text file (default: `vulnerable_packages.txt`) containing the list of package names you want to flag.

## Usage

The script is run from the command line and accepts two arguments.

```bash
python3 check_sbom.py [TARGET_FILE] [THREAT_LIST]
* TARGET_FILE (Required): The JSON file you want to scan (SBOM or lockfile).

* THREAT_LIST (Optional): Path to the text file containing bad package names. If omitted, defaults to `vulnerable_packages.txt` in the current directory.

Examples
1. Basic Run (Default List) Scans sbom.json using the default `vulnerable_packages.txt` in the same folder.
```bash
python3 check_sbom.py sbom.json

## Examples
1. **Basic Run (Default List)** Scans `sbom.json` using the default `vulnerable_packages.txt` in the same folder.
```bash
python3 check_sbom.py sbom.json




