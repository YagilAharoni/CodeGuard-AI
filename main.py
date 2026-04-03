import streamlit as st
import pandas as pd
import plotly.express as px
import time
from logic import analyze_code_security

# --- 1. Branding & Assets ---
FAVICON = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"
HERO_IMAGE = "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=1200&auto=format&fit=crop"

st.set_page_config(page_title="CodeGuard Ultra", page_icon=FAVICON, layout="wide")

# --- 2. Session State Management ---
if "api_key" not in st.session_state:
    st.session_state.api_key = ""
if "page" not in st.session_state:
    st.session_state.page = "Auditor"
if "scan_count" not in st.session_state:
    st.session_state.scan_count = 0

# --- 3. Custom CSS ---
st.markdown(f"""
    <style>
    .stApp {{ background-color: #0d1117; color: #c9d1d9; }}
    .hero-img {{
        width: 100%;
        max-height: 300px;
        object-fit: cover;
        border-radius: 12px;
        border: 1px solid #30363d;
        margin-bottom: 20px;
    }}
    .metric-card {{
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }}
    </style>
""", unsafe_allow_html=True)

# --- 4. Header ---
col_title, col_profile = st.columns([10, 1.5])
with col_title:
    st.title("🛡️ CodeGuard Ultra")

with col_profile:
    label = "👤 Profile" if st.session_state.page == "Auditor" else "🔍 Auditor"
    if st.button(label, use_container_width=True):
        st.session_state.page = "Profile" if st.session_state.page == "Auditor" else "Auditor"
        st.rerun()

# --- 5. Sidebar ---
with st.sidebar:
    st.image(FAVICON, width=60)
    st.header("Control Panel")
    st.session_state.api_key = st.text_input(
        "Groq API Key", 
        value=st.session_state.api_key, 
        type="password",
        help="Get your key at console.groq.com"
    )
    st.divider()
    st.write(f"📊 Scans: **{st.session_state.scan_count}**")

# --- 6. Content Logic ---
if st.session_state.page == "Profile":
    st.header("👤 Profile Settings")
    st.info(f"Status: {'🟢 Connected' if st.session_state.api_key else '🔴 Missing Key'}")
    if st.button("← Back to Scanning"):
        st.session_state.page = "Auditor"
        st.rerun()
else:
    st.markdown(f'<img src="{HERO_IMAGE}" class="hero-img">', unsafe_allow_html=True)
    
    if not st.session_state.api_key:
        st.warning("⚠️ API Key required.")
        st.stop()

    uploaded_files = st.file_uploader("Upload files", accept_multiple_files=True)
    
    if uploaded_files and st.button("🚀 START AUDIT", type="primary"):
        stats = {"Safe": 0, "Vulnerable": 0}
        results = []
        progress = st.progress(0)
        
        for idx, f in enumerate(uploaded_files):
            content = f.read().decode("utf-8")
            report = analyze_code_security(f.name, content, st.session_state.api_key)
            
            is_safe = "[STATUS: SAFE]" in report
            stats["Safe" if is_safe else "Vulnerable"] += 1
            results.append({"name": f.name, "safe": is_safe, "report": report, "code": content})
            progress.progress((idx + 1) / len(uploaded_files))

        # Dashboard
        st.divider()
        m1, m2, m3 = st.columns(3)
        m1.metric("Files", len(uploaded_files))
        m2.metric("Safe", stats["Safe"])
        m3.metric("Vulnerable", stats["Vulnerable"])

        fig = px.pie(values=[stats["Safe"], stats["Vulnerable"]], names=["Safe", "Vulnerable"],
                     color=["Safe", "Vulnerable"],
                     color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"}, hole=0.5)
        st.plotly_chart(fig, use_container_width=True)

        for r in results:
            with st.expander(f"{'✅' if r['safe'] else '⚠️'} {r['name']}"):
                st.markdown(r["report"].replace("[STATUS: SAFE]", "").replace("[STATUS: VULNERABLE]", ""))
        st.balloons()