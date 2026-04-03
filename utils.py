import zipfile
import io
import time
import streamlit as st

def process_uploaded_files(uploaded_files):
    """Extracts code from single files or ZIPs into a unified list."""
    files_to_scan = []
    for f in uploaded_files:
        if f.name.endswith('.zip'):
            with zipfile.ZipFile(f) as z:
                for filename in z.namelist():
                    if filename.split('.')[-1].lower() in ['py', 'cpp', 'h', 'js'] and not filename.startswith('__'):
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
    """Saves the full scan results to the session state."""
    entry = {
        "id": len(st.session_state.history),
        "time": time.strftime("%H:%M:%S"),
        "count": len(results),
        "vulns": stats["Vuln"],
        "stats": stats,
        "full_results": results # Here we save EVERYTHING
    }
    st.session_state.history.append(entry)