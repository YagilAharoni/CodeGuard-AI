import streamlit as st
from logic import analyze_code_security
from utils import process_uploaded_files, save_to_history
from ui_components import render_dashboard, render_sidebar, render_login_page, render_profile_page

# --- Assets ---
FAVICON = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"
HERO_IMAGE = "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=1200&auto=format&fit=crop"

st.set_page_config(page_title="CodeGuard Ultra", page_icon=FAVICON, layout="wide")

# --- Init States ---
if "is_authenticated" not in st.session_state: st.session_state.is_authenticated = False
if "history" not in st.session_state: st.session_state.history = []
if "api_key" not in st.session_state: st.session_state.api_key = ""
if "page" not in st.session_state: st.session_state.page = "Auditor"
if "current_view" not in st.session_state: st.session_state.current_view = None

# --- Auth Guard ---
if not st.session_state.is_authenticated:
    render_login_page(FAVICON)
    st.stop()

# --- Global UI ---
render_sidebar(FAVICON)

# --- Header & Navigation (Restored Profile Button) ---
col_t, col_p = st.columns([10, 1.5])
with col_t:
    st.title("🛡️ CodeGuard Auditor")
with col_p:
    # Toggle button for Profile/Auditor
    nav_label = "👤 Profile" if st.session_state.page == "Auditor" else "🔍 Auditor"
    if st.button(nav_label, use_container_width=True):
        st.session_state.page = "Profile" if st.session_state.page == "Auditor" else "Auditor"
        st.session_state.current_view = None # Clear view when switching
        st.rerun()

# --- Page Routing ---
if st.session_state.page == "Profile":
    render_profile_page()
else:
    # Auditor Page
    if st.session_state.current_view:
        # Action button to go back to upload screen
        if st.button("➕ Start New Scan", type="secondary"):
            st.session_state.current_view = None
            st.rerun()
        
        render_dashboard(st.session_state.current_view['stats'], st.session_state.current_view['full_results'])
    
    else:
        # Upload Screen
        st.markdown(f'<img src="{HERO_IMAGE}" style="width:100%; max-height:250px; object-fit:cover; border-radius:12px; margin-bottom:20px;">', unsafe_allow_html=True)
        uploaded = st.file_uploader("Upload Code Files (py, cpp, js, zip)", accept_multiple_files=True, type=['py','cpp','h','js','zip'])
        
        if uploaded and st.button("🚀 Run AI Security Audit", type="primary"):
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