import zipfile
import io
import time
import streamlit as st

def process_uploaded_files(uploaded_files):
    """Processes individual files or ZIP archives into a unified list"""
    files_to_scan = []
    for f in uploaded_files:
        if f.name.endswith('.zip'):
            with zipfile.ZipFile(f) as z:
                for filename in z.namelist():
                    # Filter for relevant code files only
                    extension = filename.split('.')[-1].lower()
                    if extension in ['py', 'cpp', 'h', 'js'] and not filename.startswith('__'):
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
    """Saves the scan results to the Session State history"""
    entry = {
        "id": len(st.session_state.history),
        "time": time.strftime("%H:%M:%S"),
        "count": len(results),
        "vulns": stats["Vuln"],
        "stats": stats,
        "full_results": results
    }
    st.session_state.history.append(entry)