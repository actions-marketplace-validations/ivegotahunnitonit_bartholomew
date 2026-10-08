#!/usr/bin/env python3
"""
Bartholomew Talent Review & Resume Extractor
--------------------------------------------
Inspects candidate submissions received through the Bartholomew Careers intake forum,
decodes attached resumes (PDF/DOCX/TXT), and saves them into data/resumes/.
"""

import os
import sys
import json
import base64
from pathlib import Path
from datetime import datetime

WORKSPACE = Path(__file__).resolve().parent.parent
DATA_DIR = WORKSPACE / "data"
RESUMES_DIR = DATA_DIR / "resumes"
SUBMISSIONS_FILE = DATA_DIR / "candidate_submissions.json"

def ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RESUMES_DIR.mkdir(parents=True, exist_ok=True)

def load_submissions():
    if not SUBMISSIONS_FILE.exists():
        print(f"[!] No submissions file found at {SUBMISSIONS_FILE}")
        print(f"[*] Tip: You can export all candidates from https://bartholomew.info/careers/admin by clicking 'Export All (JSON)' and placing the file at data/candidate_submissions.json")
        return []
    try:
        with open(SUBMISSIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to read {SUBMISSIONS_FILE}: {e}")
        return []

def extract_resumes():
    ensure_dirs()
    subs = load_submissions()
    if not subs:
        return

    print(f"\n=======================================================")
    print(f" BARTHOLOMEW TALENT REVIEW & RESUME VAULT")
    print(f" Total Candidates: {len(subs)}")
    print(f" Resume Extraction Target: {RESUMES_DIR}")
    print(f"=======================================================\n")

    for i, c in enumerate(subs, 1):
        name = c.get("name", "Unknown Candidate")
        email = c.get("email", "N/A")
        role = c.get("role", "General Application")
        date_recv = c.get("timestamp", "Recent")
        resume = c.get("resume")

        print(f"[{i}] {name} <{email}>")
        print(f"    Role: {role}")
        print(f"    Date: {date_recv}")
        print(f"    GitHub: {c.get('github', 'None')}")

        if resume and resume.get("dataUrl"):
            data_url = resume["dataUrl"]
            file_name = resume.get("fileName", f"resume_{i}.pdf")
            
            # Clean filename
            safe_name = f"{i:02d}_{name.replace(' ', '_')}_{file_name}"
            out_path = RESUMES_DIR / safe_name

            try:
                # data:[<mediatype>][;base64],<data>
                if ";base64," in data_url:
                    _, b64data = data_url.split(";base64,", 1)
                else:
                    b64data = data_url

                raw_bytes = base64.b64decode(b64data)
                with open(out_path, "wb") as rf:
                    rf.write(raw_bytes)
                print(f"    Resume Extracted -> {out_path.name} ({len(raw_bytes):,} bytes)")
            except Exception as ex:
                print(f"    [!] Failed to decode resume for {name}: {ex}")
        else:
            print(f"    Resume: [No file payload attached]")

        print(f"    Questionnaire Statement:")
        exp_lines = c.get("experience", "No statement").strip().splitlines()
        for line in exp_lines[:4]:
            print(f"      | {line}")
        print("-" * 55)

if __name__ == "__main__":
    extract_resumes()
