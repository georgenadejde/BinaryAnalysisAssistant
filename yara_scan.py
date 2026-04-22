import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

YARAIFY_API = "https://yaraify-api.abuse.ch/api/v1/"
AUTH_KEY = os.environ.get("YARAIFY_API_KEY")

def submit_file(filepath):
    headers = {"Auth-Key": AUTH_KEY}
    data = {
        "clamav_scan": 1,
        "unpack": 0,
    }
    with open(filepath, "rb") as f:
        files = {
            "json_data": (None, __import__("json").dumps(data), "application/json"),
            "file": (os.path.basename(filepath), f),
        }
        response = requests.post(YARAIFY_API, headers=headers, files=files)

    result = response.json()
   
    # API returns "queued" on successful submission, not "ok"
    if result.get("query_status") == "queued":
        return result["data"]["task_id"]
    return None

def get_results(task_id):
    headers = {"Auth-Key": AUTH_KEY}
    payload = {"query": "get_results", "task_id": task_id}
    response = requests.post(YARAIFY_API, headers=headers, json=payload)
    result = response.json()

    if result.get("query_status") != "ok":
        return None

    data = result["data"]

    # API returns the string "queued" when still processing
    if not isinstance(data, dict):
        return None

    return data


def parse_results(data, task_id):
    # Extract useful info from the response.
    yara_matches = data.get("static_results", [])
    clamav_matches = data.get("clamav_results", [])

    # Filter out redacted rules (non-public TLP show as "xxx")
    public_yara = [
        r for r in yara_matches
        if r.get("rule_name") != "xxx"
    ]

    return {
        "task_id": task_id,
        "yara_matches": public_yara,
        "yara_match_count": len(yara_matches),  # total including private
        "public_yara_count": len(public_yara),
        "clamav_matches": clamav_matches,
        "metadata": data.get("metadata", {}),
    }

def scan_with_yaraify(filepath, max_wait: int = 60):
    """
    Submit file and poll until results are ready.
    max_wait: seconds to wait before giving up.
    Returns parsed results dict or None on failure/timeout.
    """
    task_id = submit_file(filepath)
    if not task_id:
        return None

    waited = 0
    interval = 3  # try every 3 seconds

    while waited < max_wait:
        time.sleep(interval)
        waited += interval
        results = get_results(task_id)
        if results:
            return parse_results(results, task_id)

    return None  # timed out