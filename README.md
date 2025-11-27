# **SBOM Threat Matcher**

A lightweight, standalone Python utility for scanning Software Bills of Materials (SBOMs) and lockfiles against a list of known malicious or disallowed packages.

Designed originally to detect the **Shai-Hulud 2.0** supply chain attack, this tool is generic and can be used to check for any set of package names (e.g., malware, typo-squatting lists, or blacklisted libraries).

## **Features**

- **Versatile Input:** Supports standard **SPDX** and **CycloneDX** SBOMs, as well as **GitHub Dependency Graph** exports.
- **Direct Lockfile Support:** Can scan raw package-lock.json files (v1, v2, and v3) directly, including deep/nested dependencies.
- **GitHub API Compatible:** Automatically "unwraps" JSON responses from the GitHub API (dependency-graph/sbom).
- **Flexible matching:** Matches package names regardless of version numbers in the source list.
- **Zero Dependencies:** Runs on standard Python 3 with no need to pip install anything.

## **Prerequisites**

- Python 3.6 or higher

## **Setup**

- Save the script as `check_sbom.py`.
- Create a text file (default: `vulnerable_packages.txt`) containing the list of package names you want to flag.

## **Usage**

The script is run from the command line and accepts two arguments.

```Bash
python3 check_sbom.py [TARGET_FILE] [THREAT_LIST]
```

- **TARGET_FILE** (Required): The JSON file you want to scan (SBOM or lockfile).
- **THREAT_LIST** (Optional): Path to the text file containing bad package names. If omitted, defaults to `vulnerable_packages.txt` in the current directory.

### **Examples**

1. Basic Run (Default List)

Scans `sbom.json` using the default vulnerable_packages.txt in the same folder.

```Bash
python3 check_sbom.py sbom.json
```

2. Scanning a Lockfile

Directly checks a local project's lock file.

```Bash
python3 check_sbom.py package-lock.json
```

3. Using a Custom Threat List

Checks an SBOM against a specific list of malware (e.g., a new threat report).

```Bash
python3 check_sbom.py application.sbom.json new_malware_list.txt
```

**4. Using Absolute Paths**

```Bash
python3 check_sbom.py /tmp/repo_export.json /Users/admin/sec-lists/shai_hulud.txt
```

## **Supported Formats**

The tool automatically detects and parses the following JSON structures:

| **Format** | **Key detected** | **Notes** |
| --- | --- | --- |
| **CycloneDX** | "components" | Standard industry format. |
| --- | --- | --- |
| **SPDX** | "packages" | Standard format (used by GitHub export). |
| --- | --- | --- |
| **GitHub API** | "sbom": { ... } | Handles the API wrapper automatically. |
| --- | --- | --- |
| **NPM Lock V2/3** | "packages": { ... } | Iterates node_modules/ keys. |
| --- | --- | --- |
| **NPM Lock V1** | "dependencies" | Recursive dependency objects. |
| --- | --- | --- |
| **package.json** | "dependencies" | Simple key-value pairs. |
| --- | --- | --- |

## **Threat List Format**

The text file containing bad packages should have **one package per line**.

- The script automatically handles lines that contain version numbers or extra data (it parses the first word only).
- Case-insensitive normalization is applied.

**Valid Example (`vulnerable_packages.txt`):**

Plaintext

@ensdomains/buffer

02-echo 0.0.7

malicious-lib

@fake/package <-- comments or extra text here are ignored

## **Output Reference**

- **✅ CLEAN:** No matches found.
- **🚨 DANGER:** One or more packages from your list were found in the file.
- **❌ Error:** File not found or invalid JSON.
