import streamlit as st
from logic import analyze_code_security
from utils import process_uploaded_files, save_to_history
from ui_components import render_dashboard, render_sidebar, render_login_page

FAVICON = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"
st.set_page_config(page_title="CodeGuard Ultra", page_icon=FAVICON, layout="wide")

# Init States
if "is_authenticated" not in st.session_state: st.session_state.is_authenticated = False
if "history" not in st.session_state: st.session_state.history = []
if "api_key" not in st.session_state: st.session_state.api_key = ""
if "current_view" not in st.session_state: st.session_state.current_view = None

# Security Guard
if not st.session_state.is_authenticated:
    render_login_page(FAVICON)
    st.stop()

render_sidebar(FAVICON)
st.title("🛡️ CodeGuard Auditor")

uploaded = st.file_uploader("Upload Code", accept_multiple_files=True, type=['py','cpp','js','zip'])

if uploaded and st.button("Analyze"):
    files = process_uploaded_files(uploaded)
    stats = {"Safe": 0, "Vuln": 0}
    results = []
    
    for f in files:
        report = analyze_code_security(f['name'], f['content'], st.session_state.api_key)
        safe = "[STATUS: SAFE]" in report
        stats["Safe" if safe else "Vuln"] += 1
        results.append({"name": f['name'], "safe": safe, "report": report, "code": f['content']})
    
    save_to_history(results, stats)
    st.session_state.current_view = {"stats": stats, "full_results": results}

if st.session_state.current_view:
    render_dashboard(st.session_state.current_view['stats'], st.session_state.current_view['full_results'])