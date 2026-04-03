import streamlit as st
from logic import analyze_code_security
from utils import process_uploaded_files, save_to_history
from ui_components import (
    render_dashboard, 
    render_sidebar, 
    render_login_page, 
    render_profile_page, 
    render_about_page, 
    render_auditor_landing
)

# --- Assets & Configuration ---
FAVICON = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"
HERO_IMAGE = "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=1000&auto=format&fit=crop"

st.set_page_config(
    page_title="CodeGuard AI", 
    page_icon=FAVICON, 
    layout="wide"
)

# --- Global CSS Styling ---
st.markdown("""
    <style>
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    .metric-card { 
        background-color: #161b22; 
        border: 1px solid #30363d; 
        border-radius: 12px; 
        padding: 20px; 
        text-align: center; 
    }
    div.stButton > button:first-child {
        border-radius: 8px;
    }
    </style>
""", unsafe_allow_html=True)

# --- Initialize Session States ---
state_defaults = {
    "is_authenticated": False,
    "history": [],
    "api_key": "",
    "page": "Auditor",
    "current_view": None,
    "persona": "Student"
}

for key, value in state_defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value

# --- Authentication Guard ---
if not st.session_state.is_authenticated:
    render_login_page(FAVICON)
    st.stop()

# --- Shared UI: Sidebar ---
render_sidebar(FAVICON)

# --- Top Navigation Header ---
col_title, col_about, col_nav = st.columns([8, 2, 2])

with col_title:
    st.title("🛡️ CodeGuard AI")

with col_about:
    if st.button("ℹ️ About", use_container_width=True):
        st.session_state.page = "About"
        st.session_state.current_view = None
        st.rerun()

with col_nav:
    nav_label = "👤 My Profile" if st.session_state.page == "Auditor" else "🔍 Auditor Home"
    if st.button(nav_label, use_container_width=True):
        if st.session_state.page == "Auditor":
            st.session_state.page = "Profile"
        else:
            st.session_state.page = "Auditor"
        st.session_state.current_view = None
        st.rerun()

st.divider()

# --- Page Routing Logic ---
if st.session_state.page == "About":
    render_about_page()

elif st.session_state.page == "Profile":
    render_profile_page()

else:
    # --- Auditor Main Page Logic ---
    if st.session_state.current_view:
        # Results View (Historical or New)
        col_back, _ = st.columns([2, 8])
        with col_back:
            if st.button("➕ Start New Scan", use_container_width=True):
                st.session_state.current_view = None
                st.rerun()
        
        render_dashboard(
            st.session_state.current_view['stats'], 
            st.session_state.current_view['full_results']
        )
    
    else:
        # --- Landing & Upload View ---
        render_auditor_landing(HERO_IMAGE)

        uploaded_files = st.file_uploader(
            "Upload source files (Python, C++, JS) or a ZIP archive", 
            accept_multiple_files=True, 
            type=['py', 'cpp', 'h', 'js', 'zip']
        )
        
        if uploaded_files and st.button("🚀 Run AI Security Scan", type="primary", use_container_width=True):
            with st.spinner("Our AI agents are analyzing your codebase..."):
                files_list = process_uploaded_files(uploaded_files)
                
                if not files_list:
                    st.error("No valid source files found in the upload.")
                else:
                    stats = {"Safe": 0, "Vuln": 0, "High": 0, "Medium": 0, "Low": 0}
                    results = []
                    
                    scan_prog = st.progress(0)
                    for idx, file_item in enumerate(files_list):
                        # Analysis execution
                        report = analyze_code_security(
                            file_item['name'], 
                            file_item['content'], 
                            st.session_state.api_key
                        )
                        
                        # Parsing report for metrics
                        report_upper = report.upper()
                        is_safe = "[STATUS: SAFE]" in report_upper
                        
                        if not is_safe:
                            if "HIGH" in report_upper: stats["High"] += 1
                            elif "MEDIUM" in report_upper: stats["Medium"] += 1
                            elif "LOW" in report_upper: stats["Low"] += 1
                            stats["Vuln"] += 1
                        else:
                            stats["Safe"] += 1
                        
                        results.append({
                            "name": file_item['name'],
                            "safe": is_safe,
                            "report": report,
                            "code": file_item['content']
                        })
                        
                        scan_prog.progress((idx + 1) / len(files_list))
                    
                    # Persistence and UI update
                    save_to_history(results, stats)
                    st.session_state.current_view = {
                        "stats": stats, 
                        "full_results": results
                    }
                    st.balloons()
                    st.rerun()