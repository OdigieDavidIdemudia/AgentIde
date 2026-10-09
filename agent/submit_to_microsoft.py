#!/usr/bin/env python3
"""
Microsoft Defender False Positive Submission Script

Submits AgentIDE binaries to Microsoft for analysis:
https://www.microsoft.com/en-us/wdsi/filesubmission

Usage:
  python submit_to_microsoft.py --installer AgentIDE_Installer.exe --agent agentide.exe
"""

import argparse
import requests
import json
import os
import sys
import hashlib

# Microsoft WDSS submission endpoint
SUBMISSION_URL = "https://www.microsoft.com/en-us/wdsi/filesubmission/api/submit"

def file_hash(path, algo="sha256"):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def submit_file(filepath, description, contact_email, submit_type="home"):
    """Submit a file to Microsoft WDSS"""
    if not os.path.exists(filepath):
        print(f"ERROR: File not found: {filepath}")
        return False

    sha256 = file_hash(filepath)
    filesize = os.path.getsize(filepath)

    print(f"Submitting: {filepath}")
    print(f"  SHA256: {sha256}")
    print(f"  Size: {filesize:,} bytes")

    # Prepare multipart form
    files = {
        'file': (os.path.basename(filepath), open(filepath, 'rb'), 'application/octet-stream')
    }
    data = {
        'description': description,
        'contact_email': contact_email,
        'submit_type': submit_type,  # 'home' or 'enterprise'
        'file_type': 'executable',
        'platform': 'windows',
    }

    try:
        response = requests.post(SUBMISSION_URL, files=files, data=data, timeout=60)
        if response.status_code == 200:
            result = response.json()
            print(f"  SUCCESS: Submission ID: {result.get('submission_id', 'N/A')}")
            print(f"  Status: {result.get('status', 'submitted')}")
            return True
        else:
            print(f"  ERROR: HTTP {response.status_code}: {response.text}")
            return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Submit AgentIDE binaries to Microsoft for false positive analysis")
    parser.add_argument("--installer", help="Path to AgentIDE_Installer.exe")
    parser.add_argument("--agent", help="Path to agentide.exe")
    parser.add_argument("--email", required=True, help="Contact email for submission")
    parser.add_argument("--type", choices=["home", "enterprise"], default="enterprise", help="Submission type")
    args = parser.parse_args()

    if not args.installer and not args.agent:
        parser.error("At least one of --installer or --agent is required")

    success = True
    if args.installer:
        success &= submit_file(args.installer, "AgentIDE Installer - EDR/XDR Assessment Framework", args.email, args.type)
    if args.agent:
        success &= submit_file(args.agent, "AgentIDE Agent - EDR/XDR Assessment Agent", args.email, args.type)

    if success:
        print("\n✅ All submissions successful!")
        print("Microsoft typically responds within 24-48 hours.")
        print("Check your email for submission ID and status updates.")
        sys.exit(0)
    else:
        print("\n❌ Some submissions failed")
        sys.exit(1)

if __name__ == "__main__":
    main()