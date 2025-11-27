import json
import re
import sys
import os

# --- CONFIGURATION ---
DEFAULT_SBOM_FILENAME = "sbom.json"
DEFAULT_BAD_PACKAGES_FILE = "vulnerable_packages.txt"
# ---------------------

def normalize_name(name):
    """Normalizes package names to handle slight formatting differences."""
    # Removes 'node_modules/' prefix often found in lockfiles (e.g., node_modules/react)
    if "node_modules/" in name:
        name = name.split("node_modules/")[-1]
    return name.strip().lower()

def load_bad_packages(filepath):
    """Loads the list of infected packages into a set (ignoring versions)."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            bad_pkgs = set()
            for line in f:
                # Split line by whitespace (space or tab) to separate name from version
                parts = line.split() 
                if parts:
                    # Take the first part (the name) and normalize it
                    bad_pkgs.add(normalize_name(parts[0])) 
            return bad_pkgs
    except FileNotFoundError:
        print(f"❌ Error: Could not find vulnerable packages file: {filepath}")
        return set()

def scan_sbom(sbom_path, bad_packages):
    """Parses an SBOM or Lock File and looks for bad packages."""
    try:
        with open(sbom_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # --- FIX: UNWRAP GITHUB API RESPONSE ---
        if "sbom" in data and isinstance(data["sbom"], dict):
            sbom = data["sbom"]
        else:
            sbom = data
        # ---------------------------------------
        
        found_matches = []
        
        # 1. Check CycloneDX format (components list)
        if "components" in sbom:
            for component in sbom["components"]:
                name = normalize_name(component.get("name", ""))
                version = component.get("version", "unknown")
                if name in bad_packages:
                    found_matches.append(f"{name} @ {version}")

        # 2. Check SPDX format (standard list of packages)
        elif "packages" in sbom and isinstance(sbom["packages"], list):
            for package in sbom["packages"]:
                name = normalize_name(package.get("name", ""))
                version = package.get("versionInfo", "unknown")
                if name in bad_packages:
                    found_matches.append(f"{name} @ {version}")

        # 3. Check package-lock.json (Version 2/3 - 'packages' dictionary)
        elif "packages" in sbom and isinstance(sbom["packages"], dict):
            for pkg_path, details in sbom["packages"].items():
                if not pkg_path: continue # Skip the root entry
                name = normalize_name(pkg_path)
                version = details.get("version", "unknown")
                if name in bad_packages:
                    found_matches.append(f"{name} @ {version}")

        # 4. Check package-lock.json (Version 1) OR package.json dependencies
        elif "dependencies" in sbom:
            for name, details in sbom["dependencies"].items():
                # Handle simple "name": "version" format (package.json)
                if isinstance(details, str):
                    if normalize_name(name) in bad_packages:
                        found_matches.append(f"{name} @ {details}")
                # Handle nested "name": { "version": "..." } format (lockfile v1)
                elif isinstance(details, dict):
                    version = details.get("version", "unknown")
                    if normalize_name(name) in bad_packages:
                        found_matches.append(f"{name} @ {version}")

        return found_matches

    except json.JSONDecodeError:
        print(f"❌ Error: file '{sbom_path}' is not valid JSON.")
        return []
    except FileNotFoundError:
        print(f"❌ Error: Could not find file: {sbom_path}")
        return []

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    
    # 1. Handle SBOM/File Argument (First Argument)
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
    else:
        target_file = DEFAULT_SBOM_FILENAME

    # 2. Handle Vulnerable List Argument (Second Argument)
    if len(sys.argv) > 2:
        target_bad_pkgs = sys.argv[2]
    else:
        target_bad_pkgs = DEFAULT_BAD_PACKAGES_FILE

    # 3. Run Logic
    bad_pkgs = load_bad_packages(target_bad_pkgs)

    if bad_pkgs:
        results = scan_sbom(target_file, bad_pkgs)

        if results:
            print(f"\n🚨 DANGER in {target_file}: Found infected packages:")
            for match in results:
                print(f"  - {match}")
        else:
            # Now explicitly prints success so you know it ran
            print(f"✅ CLEAN: {os.path.basename(target_file)}")
