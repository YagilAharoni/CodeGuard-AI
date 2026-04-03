import streamlit as st
from logic import analyze_code_security
from utils import process_uploaded_files, save_to_history
from ui_components import render_dashboard

# Assets
FAVICON = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"
st.set_page_config(page_title="CodeGuard Ultra", page_icon=FAVICON, layout="wide")

# Init States
if "history" not in st.session_state: st.session_state.history = []
if "api_key" not in st.session_state: st.session_state.api_key = ""
if "page" not in st.session_state: st.session_state.page = "Auditor"
if "current_view" not in st.session_state: st.session_state.current_view = None

# Sidebar - History Logic
with st.sidebar:
    st.image(FAVICON, width=60)
    st.session_state.api_key = st.text_input("Groq API Key", value=st.session_state.api_key, type="password")
    
    st.divider()
    st.subheader("📜 Recent Scans")
    for record in reversed(st.session_state.history):
        # When clicking a history button, it loads the results into 'current_view'
        if st.button(f"🕒 {record['time']} ({record['vulns']} Vulns)", key=f"hist_{record['id']}"):
            st.session_state.current_view = record
            st.session_state.page = "Auditor"

# Header & Navigation
col_t, col_p = st.columns([10, 1.5])
with col_p:
    if st.button("👤 Profile" if st.session_state.page == "Auditor" else "🔍 Auditor"):
        st.session_state.page = "Profile" if st.session_state.page == "Auditor" else "Auditor"
        st.rerun()

# --- Page Logic ---
if st.session_state.page == "Profile":
    st.header("👤 Profile Settings")
    st.write("Configure your AI Auditor here.")
    if st.button("Clear History"):
        st.session_state.history = []
        st.rerun()

else:
    # Scanning Area
    uploaded_files = st.file_uploader("Upload Files or ZIP", type=['py', 'cpp', 'h', 'js', 'zip'], accept_multiple_files=True)
    
    if uploaded_files and st.button("🚀 START SCAN", type="primary"):
        files = process_uploaded_files(uploaded_files)
        stats = {"Safe": 0, "Vuln": 0}
        results = []
        
        prog = st.progress(0)
        for idx, item in enumerate(files):
            report = analyze_code_security(item['name'], item['content'], st.session_state.api_key)
            is_safe = "[STATUS: SAFE]" in report
            stats["Safe" if is_safe else "Vuln"] += 1
            results.append({"name": item['name'], "safe": is_safe, "report": report, "code": item['content']})
            prog.progress((idx + 1) / len(files))
        
        save_to_history(results, stats)
        st.session_state.current_view = {"stats": stats, "full_results": results}
        st.balloons()

    # Display Current View (New or from History)
    if st.session_state.current_view:
        render_dashboard(st.session_state.current_view['stats'], st.session_state.current_view['full_results'])