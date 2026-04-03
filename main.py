import streamlit as st
from logic import analyze_code_security
from utils import process_uploaded_files, save_to_history
from ui_components import (
    render_dashboard, render_sidebar, render_login_page, 
    render_profile_page, render_about_page
)

FAVICON = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"
HERO_IMAGE = "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=1200&auto=format&fit=crop"

st.set_page_config(page_title="CodeGuard AI", page_icon=FAVICON, layout="wide")

# CSS for a cleaner, slightly transparent background feel
st.markdown("""
    <style>
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    .metric-card { 
        background-color: rgba(22, 27, 34, 0.8); 
        border: 1px solid #30363d; 
        border-radius: 12px; 
        padding: 15px; 
        text-align: center; 
    }
    .stExpander { border: 1px solid #30363d !important; background-color: rgba(13, 17, 23, 0.5); }
    </style>
""", unsafe_allow_html=True)

if "is_authenticated" not in st.session_state: st.session_state.is_authenticated = False
if "history" not in st.session_state: st.session_state.history = []
if "api_key" not in st.session_state: st.session_state.api_key = ""
if "page" not in st.session_state: st.session_state.page = "Auditor"
if "current_view" not in st.session_state: st.session_state.current_view = None

if not st.session_state.is_authenticated:
    render_login_page(FAVICON)
    st.stop()

render_sidebar(FAVICON)

# Navigation Header
col_t, col_a, col_p = st.columns([8, 2, 2])
with col_t: st.title("🛡️ CodeGuard AI")
with col_a: 
    if st.button("ℹ️ About", use_container_width=True): st.session_state.page = "About"; st.rerun()
with col_p:
    nav_label = "👤 Profile" if st.session_state.page == "Auditor" else "🔍 Auditor"
    if st.button(nav_label, use_container_width=True):
        st.session_state.page = "Profile" if st.session_state.page == "Auditor" else "Auditor"
        st.rerun()

if st.session_state.page == "About":
    render_about_page()
elif st.session_state.page == "Profile":
    render_profile_page()
else:
    if st.session_state.current_view:
        if st.button("➕ New Scan"): st.session_state.current_view = None; st.rerun()
        render_dashboard(st.session_state.current_view['stats'], st.session_state.current_view['full_results'])
    else:
        st.image(HERO_IMAGE, use_container_width=True)
        uploaded = st.file_uploader("Upload Code", accept_multiple_files=True, type=['py','cpp','h','js','zip'])
        if uploaded and st.button("🚀 Analyze Base", type="primary", use_container_width=True):
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