import streamlit as st
import pandas as pd
import plotly.express as px
import time
import requests
from streamlit_lottie import st_lottie
from logic import analyze_code_security

# --- 1. Basic Configuration & Branding ---
FAVICON = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"
HERO_IMAGE = "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=600&auto=format&fit=crop"

st.set_page_config(page_title="CodeGuard Ultra", page_icon=FAVICON, layout="wide")

# --- 2. Session State (Temporary Memory) ---
if "api_key" not in st.session_state: st.session_state.api_key = ""
if "page" not in st.session_state: st.session_state.page = "Auditor"

# --- 3. Custom CSS (Cyber Theme) ---
st.markdown("""
    <style>
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    .hero-img { width: 100%; max-height: 250px; object-fit: cover; border-radius: 12px; margin-bottom: 20px; border: 1px solid #30363d; }
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 15px;
        text-align: center;
    }
    </style>
""", unsafe_allow_html=True)

# --- 4. Top Navigation Bar (Header) ---
col_title, col_profile = st.columns([10, 1.5])
with col_title:
    st.title("🛡️ CodeGuard Auditor")
with col_profile:
    # Top-right Profile Button
    if st.button("👤 Profile", use_container_width=True):
        st.session_state.page = "Profile" if st.session_state.page == "Auditor" else "Auditor"

# --- 5. Sidebar (Settings) ---
with st.sidebar:
    st.image(FAVICON, width=60)
    st.header("Settings")
    # API Key is entered here once and stays for the session
    st.session_state.api_key = st.text_input("Groq API Key", value=st.session_state.api_key, type="password")
    st.divider()
    st.caption("v2.5 - Local Edition")

# --- 6. Page Logic ---

if st.session_state.page == "Profile":
    # --- Profile View ---
    st.header("👤 Your Profile")
    st.write("This is your local session profile.")
    st.info(f"Current API Key: {'Set' if st.session_state.api_key else 'Not Set'}")
    
    if st.button("← Back to Scanning"):
        st.session_state.page = "Auditor"
        st.rerun()

else:
    # --- Auditor View ---
    st.markdown(f'<img src="{HERO_IMAGE}" class="hero-img">', unsafe_allow_html=True)
    
    if not st.session_state.api_key:
        st.warning("⚠️ Please enter your Groq API Key in the sidebar to start auditing.")
        st.stop()

    uploaded_files = st.file_uploader("Upload Codebase", accept_multiple_files=True)
    
    if uploaded_files and st.button("🚀 RUN SECURITY SCAN", type="primary"):
        stats = {"Safe": 0, "Vulnerable": 0}
        results = []
        
        progress = st.progress(0)
        status = st.empty()

        for idx, f in enumerate(uploaded_files):
            status.markdown(f"🔍 Analyzing: `{f.name}`...")
            content = f.read().decode("utf-8")
            
            # API Call to Logic
            report = analyze_code_security(f.name, content, st.session_state.api_key)
            
            is_safe = "[STATUS: SAFE]" in report
            stats["Safe" if is_safe else "Vulnerable"] += 1
            results.append({"name": f.name, "safe": is_safe, "report": report, "code": content})
            
            progress.progress((idx + 1) / len(uploaded_files))

        status.empty()

        # --- Dashboard (Executive Summary) ---
        st.divider()
        st.subheader("📊 Executive Summary")
        m1, m2, m3 = st.columns(3)
        m1.markdown(f'<div class="metric-card">Total Files<br><h2>{len(uploaded_files)}</h2></div>', unsafe_allow_html=True)
        m2.markdown(f'<div class="metric-card">Safe<br><h2 style="color:#39ff14">{stats["Safe"]}</h2></div>', unsafe_allow_html=True)
        m3.markdown(f'<div class="metric-card">Vulnerable<br><h2 style="color:#ff3131">{stats["Vulnerable"]}</h2></div>', unsafe_allow_html=True)

        # Fixed Color Chart Logic
        fig = px.pie(
            values=[stats["Safe"], stats["Vulnerable"]], 
            names=["Safe", "Vulnerable"],
            hole=0.5,
            color=["Safe", "Vulnerable"],
            color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"}
        )
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white", height=350)
        st.plotly_chart(fig, use_container_width=True)

        # --- Detailed Reports ---
        st.subheader("📂 Detailed Audit Logs")
        for r in results:
            icon = "✅" if r["safe"] else "⚠️"
            with st.expander(f"{icon} {r['name']}", expanded=not r["safe"]):
                st.markdown(r["report"].replace("[STATUS: SAFE]", "").replace("[STATUS: VULNERABLE]", ""))
                st.divider()
                st.code(r["code"])
        st.balloons()