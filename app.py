import streamlit as st
import tempfile, os
from static_analysis import extract_features
from scan_file import scan_with_vt
from analyzer import analyze
from yara_scan import scan_with_yaraify

st.set_page_config(page_title="Binary Analysis A(I)ssistant", page_icon="🔬")
st.title("Binary Analysis A(I)ssistant")
st.caption("Static analysis + LLM-powered threat assessment")

uploaded_file = st.file_uploader("Upload a binary (.elf/.exe/.dll) file")

# Clear session state when a new file is uploaded or removed
current_file = uploaded_file.name if uploaded_file else None
if st.session_state.get("uploaded_filename") != current_file:
    for key in ["ai_report", "vt_report", "vt_error", "yara_report", "yara_error", "features", "tmp_path"]:
        st.session_state.pop(key, None)
    st.session_state["uploaded_filename"] = current_file

if uploaded_file is not None:

    # Only write the file once — reuse on reruns
    if "tmp_path" not in st.session_state:
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(uploaded_file.read())
        tmp.close()
        tmp_path = os.path.join(os.path.dirname(tmp.name), uploaded_file.name)
        os.rename(tmp.name, tmp_path)
        st.session_state["tmp_path"] = tmp_path
    else:
        tmp_path = st.session_state["tmp_path"]

    # Only extract features once
    if "features" not in st.session_state:
        with st.spinner("Extracting features..."):
            st.session_state["features"] = extract_features(tmp_path)

    features = st.session_state["features"]

    # Static analysis metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Entropy", f"{features['entropy']} / 8.0")
    col2.metric("Strings found", len(features["strings"]))
    col3.metric("Imports found", len(features["imports"]))

    st.markdown("#### File type")
    st.code(features["file"].split(":", 1)[-1].strip())

    with st.expander("Raw strings extracted"):
        st.code("\n".join(features["strings"]))

    with st.expander("Imported functions"):
        st.code("\n".join(features["imports"]) or "None found")

    st.markdown("---")

    # Buttons
    col_ai, col_vt, col_yara = st.columns(3)

    # AI Analysis
    with col_ai:
        if st.button("Analyze with AI", use_container_width=True):
            with st.spinner("Running LLM analysis..."):
                vt_data = st.session_state.get("vt_report")
                yara_data = st.session_state.get("yara_report")
                report = analyze(features, vt_data, yara_data)
            st.session_state["ai_report"] = report

    if "ai_report" in st.session_state:
        with st.expander(f"Threat Report — {uploaded_file.name}", expanded=True):
            st.markdown(st.session_state["ai_report"])
        st.download_button(
            "Download AI Report",
            st.session_state["ai_report"],
            file_name=f"analysis_{uploaded_file.name}.txt"
        )

    # VirusTotal
    with col_vt:
        if st.button("Scan with VirusTotal", use_container_width=True):
            with st.spinner("Scanning..."):
                try:
                    st.session_state["vt_report"] = scan_with_vt(features["hash"])
                    st.session_state["vt_error"] = None
                except Exception as e:
                    st.session_state["vt_error"] = str(e)
                    st.session_state["vt_report"] = None

    if st.session_state.get("vt_error"):
        st.warning(f"VirusTotal: {st.session_state['vt_error']}")

    if st.session_state.get("vt_report"):
        vt = st.session_state["vt_report"]
        malicious = vt["malicious_engines"]
        suspicious = vt["suspicious_engines"]
        total = vt["total_engines"]
        flagged = vt["flagged_by"]

        if malicious > 5:
            st.error(f"🔴 MALICIOUS — {malicious}/{total} engines flagged this file")
        elif malicious > 0 or suspicious > 0:
            st.warning(f"🟡 SUSPICIOUS — {malicious + suspicious}/{total} engines flagged this file")
        else:
            st.success(f"🟢 CLEAN — 0/{total} engines flagged this file")

        with st.expander(f"VirusTotal results — {uploaded_file.name}", expanded=True):
            col1, col2, col3 = st.columns(3)
            col1.metric("Malicious", malicious)
            col2.metric("Suspicious", suspicious)
            col3.metric("Total engines", total)

            if vt["known_names"]:
                st.markdown("**Known filenames**")
                st.code(", ".join(vt["known_names"]))
            if vt["tags"]:
                st.markdown("**File type tag**")
                st.code(vt["tags"])
            if vt["first_seen"]:
                st.markdown(f"**First seen:** {vt['first_seen']}")

            st.markdown(f"**Full SHA-256:** `{features['hash']}`")

            if flagged:
                st.markdown("**Flagged by**")
                rows = [
                    {"Engine": engine, "Category": data["category"], "Result": data.get("result") or "—"}
                    for engine, data in flagged.items()
                ]
                st.dataframe(rows, use_container_width=True)
            else:
                st.info("No engines flagged this file.")

    # YARAify
    with col_yara:
        if st.button("Scan with YARAify", use_container_width=True):
            with st.spinner("Submitting to YARAify... (may take ~30s)"):
                try:
                    st.session_state["yara_report"] = scan_with_yaraify(tmp_path)
                    st.session_state["yara_error"] = None
                except Exception as e:
                    st.session_state["yara_error"] = str(e)
                    st.session_state["yara_report"] = None

    if st.session_state.get("yara_error"):
        st.warning(f"YARAify: {st.session_state['yara_error']}")

    if st.session_state.get("yara_report"):
        yara = st.session_state["yara_report"]
        yara_count = yara["yara_match_count"]
        clam_count = len(yara["clamav_matches"])

        if yara_count > 0:
            st.error(f"🔴 YARA — {yara['public_yara_count']} public rules matched ({yara_count} total including private)")
        else:
            st.success("🟢 YARA — No rules matched")

        with st.expander(f"YARAify results — {uploaded_file.name}", expanded=True):
            col1, col2 = st.columns(2)
            col1.metric("YARA matches", yara_count)
            col2.metric("ClamAV matches", clam_count)

            if yara["yara_matches"]:
                st.markdown("**Matched YARA rules**")
                rows = [
                    {
                        "Rule": r["rule_name"],
                        "Author": r.get("author") or "—",
                        "Description": r.get("description") or "—",
                        "TLP": r.get("tlp") or "—",
                    }
                    for r in yara["yara_matches"]
                ]
                st.dataframe(rows, use_container_width=True)

            if yara["clamav_matches"]:
                st.markdown("**ClamAV detections**")
                st.code("\n".join(yara["clamav_matches"]))

            st.caption(f"Task ID: `{yara['task_id']}`")

    st.markdown("---")
    st.caption("⚠️ Static analysis only. Always verify with dynamic analysis before drawing conclusions.")

else:
    # Clean up temp file if user removes the upload
    if "tmp_path" in st.session_state:
        try:
            os.remove(st.session_state["tmp_path"])
        except FileNotFoundError:
            pass
        del st.session_state["tmp_path"]