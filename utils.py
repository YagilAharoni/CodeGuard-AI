import zipfile
import io
import time
import streamlit as st

def process_uploaded_files(uploaded_files):
    files_to_scan = []
    for f in uploaded_files:
        if f.name.endswith('.zip'):
            with zipfile.ZipFile(f) as z:
                for filename in z.namelist():
                    ext = filename.split('.')[-1].lower()
                    if ext in ['py', 'cpp', 'h', 'js'] and not filename.startswith('__'):
                        with z.open(filename) as internal_file:
                            files_to_scan.append({
                                "name": filename,
                                "content": internal_file.read().decode("utf-8", errors="ignore")
                            })
        else:
            files_to_scan.append({
                "name": f.name,
                "content": f.read().decode("utf-8", errors="ignore")
            })
    return files_to_scan

def save_to_history(results, stats):
    if "history" not in st.session_state:
        st.session_state.history = []
    entry = {
        "id": len(st.session_state.history),
        "time": time.strftime("%H:%M:%S"),
        "count": len(results),
        "vulns": stats.get("Vuln", 0),
        "stats": stats,
        "full_results": results
    }
    st.session_state.history.append(entry)