from dotenv import load_dotenv
import vt
import os

def scan_with_vt(hash):
    load_dotenv()
    with vt.Client(os.environ.get('VT_API_KEY')) as client:
        file = client.get_object(f"/files/{hash}")
        stats = file.last_analysis_stats
        results = file.last_analysis_results
        flagged = {
            engine: data
            for engine, data in results.items() if data["category"] in ("malicious", "suspicious")
        }
        return {
            "malicious_engines": stats["malicious"],
            "suspicious_engines": stats["suspicious"],
            "total_engines": sum(stats.values()),
            "known_names": file.names,
            "first_seen": file.first_submission_date,
            "tags": file.type_tag,
            "flagged_by": flagged,
        }
