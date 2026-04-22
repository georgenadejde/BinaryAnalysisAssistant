from google import genai
from google.genai import types
from dotenv import load_dotenv
import os
from static_analysis import interpret_entropy

def load_api_key():
    load_dotenv()
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
    client = genai.Client(api_key=GEMINI_API_KEY)
    return client

SYSTEM_PROMPT = '''You are an expert malware analyst and reverse engineer 
                with 10+ years of experience in threat intelligence. You analyze static 
                features of binaries and produce clear, actionable threat reports.
                Be precise. Flag specific indicators. Never speculate wildly — 
                distinguish between confirmed and suspected behavior.'''


def build_yara_section(yara_data):
    if not yara_data:
        return "YARAIFY SCAN: Not scanned."

    if yara_data["yara_match_count"] == 0 and not yara_data["clamav_matches"]:
        return "YARAIFY SCAN: No YARA or ClamAV rules matched."

    yara_str = "\n".join(
        f"  - {r['rule_name']} (by {r.get('author') or 'unknown'}): {r.get('description') or 'no description'}"
        for r in yara_data["yara_matches"]
    ) or "  None public"

    clam_str = "\n".join(f"  - {c}" for c in yara_data["clamav_matches"]) or "  None"

    return f"""YARAIFY SCAN RESULTS:
            Total YARA matches: {yara_data['yara_match_count']} ({yara_data['public_yara_count']} public)
            Public YARA rules matched:
            {yara_str}
            ClamAV detections:
            {clam_str}"""

def build_vt_section(vt_data):
    if not vt_data:
        return "VIRUSTOTAL: Not scanned or hash not found in database."

    flagged = vt_data.get("flagged_by", {})
    flagged_str = "\n".join(
        f"  - {engine}: [{data['category']}] {data.get('result') or '—'}"
        for engine, data in flagged.items()
    )

    known_names = ", ".join(vt_data.get("known_names") or []) or "Unknown"

    return f"""VIRUSTOTAL SCAN RESULTS:
            Detection ratio: {vt_data['malicious_engines']} malicious, {vt_data['suspicious_engines']} suspicious out of {vt_data['total_engines']} engines
            Known filenames: {known_names}
            First seen: {vt_data.get('first_seen')}
            File type tag: {vt_data.get('tags')}
            Flagged by: {flagged_str}
            """

def build_prompt(features, vt_data, yara_data):
    imports_str = "\n".join(features["imports"]) 
    strings_str = "\n".join(features["strings"])
    vt_section = build_vt_section(vt_data)
    yara_section = build_yara_section(yara_data)

    return f"""Analyze this binary based on static analysis features and VirusTotal data.

            FILE TYPE: {features["file"]}
            SHA-256: {features['hash']}
            ENTROPY: {features["entropy"]} / 8.0 ({interpret_entropy(features['entropy'])})

            VirusTotal Scan:
            {vt_section}

            IMPORTED FUNCTIONS:
            {imports_str}

            EXTRACTED STRINGS:
            {strings_str}

            YARA RULES:
            {yara_section}

            Provide a structured report with the following sections:
            1. THREAT ASSESSMENT — Benign / Suspicious / Likely Malicious. If VirusTotal data is available, weight it heavily.
            2. BEHAVIORAL INDICATORS — What does this binary likely do based on imports and strings?
            3. RED FLAGS — Specific strings, imports, or VirusTotal detections that are concerning and why.
            4. MALWARE FAMILY — If VirusTotal engine results or static patterns match a known family, name it.
            5. ANALYST RECOMMENDATIONS — What to investigate next?
            6. CONFIDENCE — How confident are you and why? Factor in whether VirusTotal data was available.
            """

def analyze(features , vt_data, yara_data):
    client = load_api_key()

    response = client.models.generate_content(
        model="gemini-3-flash-preview",
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT),
        contents=build_prompt(features, vt_data, yara_data)
    )

    return response.text