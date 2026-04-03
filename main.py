import streamlit as st
from logic import analyze_code_security
from utils import process_uploaded_files, save_to_history
from ui_components import render_dashboard, render_sidebar, render_login_page

FAVICON = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"
st.set_page_config(page_title="CodeGuard Ultra", page_icon=FAVICON, layout="wide")

# Static CSS
st.markdown("""
    <style>
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    .metric-card { background-color: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px; text-align: center; }
    </style>
""", unsafe_allow_html=True)

# Initialize States
if "is_authenticated" not in st.session_state: st.session_state.is_authenticated = False
if "history" not in st.session_state: st.session_state.history = []
if "api_key" not in st.session_state: st.session_state.api_key = ""
if "current_view" not in st.session_state: st.session_state.current_view = None

if not st.session_state.is_authenticated:
    render_login_page(FAVICON)
    st.stop()

render_sidebar(FAVICON)
st.title("🛡️ CodeGuard Auditor")

uploaded = st.file_uploader("Upload Code Files", accept_multiple_files=True, type=['py','cpp','h','js','zip'])

if uploaded and st.button("🚀 Analyze Base", type="primary"):
    files = process_uploaded_files(uploaded)
    stats = {"Safe": 0, "Vuln": 0}
    results = []
    
    prog = st.progress(0)
    for idx, f in enumerate(files):
        report = analyze_code_security(f['name'], f['content'], st.session_state.api_key)
        safe = "[STATUS: SAFE]" in report
        stats["Safe" if safe else "Vuln"] += 1
        results.append({"name": f['name'], "safe": safe, "report": report, "code": f['content']})
        prog.progress((idx + 1) / len(files))
    
    save_to_history(results, stats)
    st.session_state.current_view = {"stats": stats, "full_results": results}
    st.rerun()

if st.session_state.current_view:
    render_dashboard(st.session_state.current_view['stats'], st.session_state.current_view['full_results'])