import streamlit as st
import pandas as pd
import plotly.express as px
import time
import zipfile
import io
from logic import analyze_code_security

# --- 1. Branding & Assets ---
FAVICON = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"
HERO_IMAGE = "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=1200&auto=format&fit=crop"

st.set_page_config(page_title="CodeGuard Ultra", page_icon=FAVICON, layout="wide")

# --- 2. Session State Management ---
if "api_key" not in st.session_state: st.session_state.api_key = ""
if "page" not in st.session_state: st.session_state.page = "Auditor"
if "history" not in st.session_state: st.session_state.history = [] # For Scan History

# --- 3. Custom CSS ---
st.markdown("""
    <style>
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    .hero-img { width: 100%; max-height: 250px; object-fit: cover; border-radius: 12px; margin-bottom: 20px; border: 1px solid #30363d; }
    .metric-card { background-color: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 15px; text-align: center; }
    .history-item { padding: 10px; border-bottom: 1px solid #30363d; font-size: 0.9em; }
    </style>
""", unsafe_allow_html=True)

# --- 4. Header (Title & Profile Button) ---
col_title, col_profile = st.columns([10, 1.5])
with col_title:
    st.title("🛡️ CodeGuard Ultra")

with col_profile:
    label = "👤 Profile" if st.session_state.page == "Auditor" else "🔍 Auditor"
    if st.button(label, use_container_width=True):
        st.session_state.page = "Profile" if st.session_state.page == "Auditor" else "Auditor"
        st.rerun()

# --- 5. Sidebar (Controls & History) ---
with st.sidebar:
    st.image(FAVICON, width=60)
    st.header("Control Panel")
    
    st.session_state.api_key = st.text_input(
        "Groq API Key", value=st.session_state.api_key, type="password",
        help="""
        ### 🔑 How to get your API Key:
        1. Go to [console.groq.com](https://console.groq.com/keys)
        2. Click 'Create API Key'.
        3. Copy and paste it here.
        """
    )
    
    st.divider()
    st.subheader("📜 Recent Scans")
    if not st.session_state.history:
        st.caption("No scans yet in this session.")
    else:
        for i, record in enumerate(reversed(st.session_state.history[-5:])): # Show last 5
            st.markdown(f"**{record['time']}**")
            st.caption(f"📁 {record['count']} files | {record['vulns']} issues")
            st.divider()

# --- 6. Page Logic ---

if st.session_state.page == "Profile":
    st.header("👤 Profile & Instructions")
    st.info("Status: " + ("🟢 Connected" if st.session_state.api_key else "🔴 Key Missing"))
    if st.button("← Back to Auditor"):
        st.session_state.page = "Auditor"
        st.rerun()

else:
    st.markdown(f'<img src="{HERO_IMAGE}" class="hero-img">', unsafe_allow_html=True)
    
    if not st.session_state.api_key:
        st.warning("⚠️ Please provide a Groq API Key in the sidebar.")
        st.stop()

    # Support for both single files and ZIPs
    uploaded_files = st.file_uploader("Upload Files or ZIP Project", 
                                    accept_multiple_files=True, 
                                    type=['py', 'cpp', 'h', 'js', 'zip'])
    
    if uploaded_files and st.button("🚀 START SCAN", type="primary"):
        files_to_scan = []
        
        # Process ZIP files and normal files
        for f in uploaded_files:
            if f.name.endswith('.zip'):
                with zipfile.ZipFile(f) as z:
                    for filename in z.namelist():
                        # Filter only code files and ignore hidden/system files
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

        if not files_to_scan:
            st.error("No valid code files found to scan.")
            st.stop()

        stats = {"Safe": 0, "Vuln": 0}
        results = []
        progress = st.progress(0)
        
        for idx, item in enumerate(files_to_scan):
            report = analyze_code_security(item['name'], item['content'], st.session_state.api_key)
            is_safe = "[STATUS: SAFE]" in report
            stats["Safe" if is_safe else "Vuln"] += 1
            results.append({"name": item['name'], "safe": is_safe, "report": report, "code": item['content']})
            progress.progress((idx + 1) / len(files_to_scan))

        # Save to History
        st.session_state.history.append({
            "time": time.strftime("%H:%M:%S"),
            "count": len(files_to_scan),
            "vulns": stats["Vuln"]
        })

        # --- Dashboard ---
        st.divider()
        m1, m2, m3 = st.columns(3)
        m1.metric("Total Files", len(files_to_scan))
        m2.metric("Safe", stats["Safe"])
        m3.metric("Vulnerable", stats["Vuln"])

        fig = px.pie(values=[stats["Safe"], stats["Vuln"]], names=["Safe", "Vulnerable"],
                     color=["Safe", "Vulnerable"],
                     color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"}, hole=0.5)
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white")
        st.plotly_chart(fig, use_container_width=True)

        for r in results:
            with st.expander(f"{'✅' if r['safe'] else '⚠️'} {r['name']}"):
                st.markdown(r["report"].replace("[STATUS: SAFE]", "").replace("[STATUS: VULNERABLE]", ""))
        st.balloons()