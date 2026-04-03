import streamlit as st
from logic import analyze_code_security
from utils import process_uploaded_files, save_to_history
from ui_components import render_dashboard, render_profile_page, render_sidebar, render_login_page

FAVICON = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"
HERO_IMAGE = "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=1200&auto=format&fit=crop"

st.set_page_config(page_title="CodeGuard Ultra", page_icon=FAVICON, layout="wide")

if "is_authenticated" not in st.session_state: st.session_state.is_authenticated = False
if "history" not in st.session_state: st.session_state.history = []
if "api_key" not in st.session_state: st.session_state.api_key = ""
if "page" not in st.session_state: st.session_state.page = "Auditor"
if "current_view" not in st.session_state: st.session_state.current_view = None

st.markdown(f"""
    <style>
    .stApp {{ background-color: #0d1117; color: #c9d1d9; }}
    .hero-img {{ width: 100%; max-height: 250px; object-fit: cover; border-radius: 12px; margin-bottom: 20px; border: 1px solid #30363d; }}
    .metric-card {{ background-color: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px; text-align: center; }}
    </style>
""", unsafe_allow_html=True)

if not st.session_state.is_authenticated:
    render_login_page(FAVICON)
    st.stop()

render_sidebar(FAVICON)

col_t, col_p = st.columns([10, 1.5])
with col_t: st.title("🛡️ CodeGuard Ultra")
with col_p:
    label = "👤 Profile" if st.session_state.page == "Auditor" else "🔍 Auditor"
    if st.button(label, use_container_width=True):
        st.session_state.page = "Profile" if st.session_state.page == "Auditor" else "Auditor"
        st.rerun()

if st.session_state.page == "Profile":
    render_profile_page()
else:
    st.markdown(f'<img src="{HERO_IMAGE}" class="hero-img">', unsafe_allow_html=True)
    
    files_input = st.file_uploader("Upload Files or ZIP", type=['py', 'cpp', 'h', 'js', 'zip'], accept_multiple_files=True)
    
    if files_input and st.button("🚀 SCAN CODEBASE", type="primary"):
        processed_files = process_uploaded_files(files_input)
        stats = {"Safe": 0, "Vuln": 0}
        results = []
        
        prog = st.progress(0)
        for idx, item in enumerate(processed_files):
            report = analyze_code_security(item['name'], item['content'], st.session_state.api_key)
            is_safe = "[STATUS: SAFE]" in report
            stats["Safe" if is_safe else "Vuln"] += 1
            results.append({"name": item['name'], "safe": is_safe, "report": report, "code": item['content']})
            prog.progress((idx + 1) / len(processed_files))
        
        save_to_history(results, stats)
        st.session_state.current_view = {"stats": stats, "full_results": results}
        st.balloons()

    if st.session_state.current_view:
        render_dashboard(st.session_state.current_view['stats'], st.session_state.current_view['full_results'])