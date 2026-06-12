#!/usr/bin/env python3
import os
import re
import sys
import subprocess

# Regex patterns
COMMIT_PATTERN = re.compile(r'(?:\bcommit\b|\bsha\b|\bat\b|\bfeat\b)\s+`?([0-9a-f]{7,40})`?', re.IGNORECASE)
FEATURE_PATTERNS = [
    re.compile(r'(?:\bfeature\s+`?([A-Za-z0-9_-]+)`?|\bgated\s+behind\s+`?([A-Za-z0-9_-]+)`?|\bgated\s+by\s+`?([A-Za-z0-9_-]+)`?|\bfeatures\s+`?([A-Za-z0-9_-]+)`?)', re.IGNORECASE),
    re.compile(r'`([A-Za-z0-9_-]+)`\s+(?:\bfeature\b|\bCargo\s+feature\b)', re.IGNORECASE)
]

def get_declared_features():
    declared = set()
    # Find all Cargo.toml files
    for root, dirs, files in os.walk('.'):
        # Skip node_modules and target/out
        if 'node_modules' in root or 'target' in root or 'out' in root:
            continue
        for f in files:
            if f == 'Cargo.toml':
                path = os.path.join(root, f)
                with open(path, 'r', encoding='utf-8') as file_obj:
                    content = file_obj.read()
                    # Find [features] section
                    in_features = False
                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith('[') and line.endswith(']'):
                            if line == '[features]':
                                in_features = True
                            else:
                                in_features = False
                            continue
                        if in_features and line and not line.startswith('#'):
                            parts = line.split('=')
                            if len(parts) >= 1:
                                feature_name = parts[0].strip()
                                feature_name = feature_name.strip('"').strip("'")
                                if feature_name:
                                    declared.add(feature_name.lower())
    return declared

def check_commit_ancestor(sha):
    # Check if commit exists
    res = subprocess.run(['git', 'cat-file', '-t', sha], capture_output=True)
    if res.returncode != 0:
        return False, "does not exist"
    # Check if ancestor of HEAD
    res = subprocess.run(['git', 'merge-base', '--is-ancestor', sha, 'HEAD'], capture_output=True)
    if res.returncode != 0:
        return False, "is not an ancestor of HEAD"
    return True, ""

def is_valid_feature_candidate(name):
    # Cargo features must be lowercase
    if not name.islower():
        return False
    # Whitelist of short names
    if name in ('ads', 'zk'):
        return True
    # Require at least one underscore or hyphen to prevent common English words
    if '_' not in name and '-' not in name:
        return False
    # Exclude specific false positive words
    if name in ('mneme-store', 'aws-kms-feature'):
        return False
    return True

def main():
    declared_features = get_declared_features()
    md_files = []
    for root, dirs, files in os.walk('.'):
        # Exclude node_modules, target, out, experimental, .git
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('target', 'out', 'experimental', 'node_modules')]
        for f in files:
            if f.endswith('.md'):
                md_files.append(os.path.join(root, f))

    violations = 0
    checked_commits = {}

    for path in md_files:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Find commit citations
            for match in COMMIT_PATTERN.finditer(content):
                sha = match.group(1).lower()
                if sha not in checked_commits:
                    is_valid, reason = check_commit_ancestor(sha)
                    checked_commits[sha] = (is_valid, reason)
                
                is_valid, reason = checked_commits[sha]
                if not is_valid:
                    # Enforce checking for hex strings that are likely commits (length >= 7)
                    if reason == "is not an ancestor of HEAD" or (reason == "does not exist" and len(sha) >= 7):
                        print(f"VIOLATION in {path}: commit {sha} {reason}")
                        violations += 1

            # Find feature citations
            features_found = set()
            for pattern in FEATURE_PATTERNS:
                for match in pattern.finditer(content):
                    for g in match.groups():
                        if g:
                            # Skip constants/variables that are uppercase
                            if any(c.isupper() for c in g):
                                continue
                            candidate = g.lower()
                            if is_valid_feature_candidate(candidate):
                                features_found.add(candidate)
                            
            for feat in features_found:
                if feat not in declared_features:
                    print(f"VIOLATION in {path}: Cargo feature '{feat}' is not declared in any Cargo.toml")
                    violations += 1

    if violations > 0:
        print(f"Total violations found: {violations}")
        sys.exit(1)
    else:
        print("Claims lint passed successfully.")
        sys.exit(0)

if __name__ == '__main__':
    main()
