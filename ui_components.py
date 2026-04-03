import streamlit as st
import plotly.express as px

def render_login_page(favicon):
    """Displays the login screen for API Key entry"""
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.image(favicon, width=100)
        st.title("🛡️ CodeGuard Access")
        st.write("Please enter your Groq API Key to unlock the system.")
        
        api_input = st.text_input("Groq API Key", type="password", help="Generate a key at console.groq.com")
        
        if st.button("Unlock System 🚀", use_container_width=True):
            if api_input.startswith("gsk_"):
                st.session_state.api_key = api_input
                st.session_state.is_authenticated = True
                st.rerun()
            else:
                st.error("Invalid key. The key must start with 'gsk_'.")

def render_sidebar(favicon):
    """Displays the sidebar with history and logout options"""
    with st.sidebar:
        st.image(favicon, width=60)
        st.header("Control Panel")
        
        if st.button("Logout / Change Key", use_container_width=True):
            st.session_state.is_authenticated = False
            st.session_state.api_key = ""
            st.rerun()

        st.divider()
        st.subheader("📜 Recent Scans")
        if not st.session_state.history:
            st.caption("No saved scans.")
        for record in reversed(st.session_state.history):
            if st.button(f"🕒 {record['time']} ({record['vulns']} Vulns)", key=f"hist_{record['id']}", use_container_width=True):
                st.session_state.current_view = record
                st.session_state.page = "Auditor"

def render_dashboard(stats, results):
    """Displays scan results, metrics, and charts"""
    st.divider()
    st.subheader("📊 Executive Summary")
    
    m1, m2, m3 = st.columns(3)
    with m1: st.markdown(f'<div class="metric-card">Files<br><h2>{len(results)}</h2></div>', unsafe_allow_html=True)
    with m2: st.markdown(f'<div class="metric-card">Safe<br><h2 style="color:#39ff14">{stats["Safe"]}</h2></div>', unsafe_allow_html=True)
    with m3: st.markdown(f'<div class="metric-card">Vulns<br><h2 style="color:#ff3131">{stats["Vuln"]}</h2></div>', unsafe_allow_html=True)

    fig = px.pie(values=[stats["Safe"], stats["Vuln"]], names=["Safe", "Vulnerable"],
                 hole=0.5, color=["Safe", "Vulnerable"],
                 color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"})
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white", height=350)
    st.plotly_chart(fig, use_container_width=True)

    for r in results:
        icon = "✅" if r["safe"] else "⚠️"
        with st.expander(f"{icon} {r['name']}"):
            t1, t2 = st.tabs(["Security Report", "Source Code"])
            t1.markdown(r["report"])
            t2.code(r["code"])

def render_profile_page():
    """Displays the profile page and user settings"""
    st.header("👤 Profile & Settings")
    st.divider()
    if st.button("Clear Scan History"):
        st.session_state.history = []
        st.session_state.current_view = None
        st.rerun()
    if st.button("← Back to Auditor"):
        st.session_state.page = "Auditor"
        st.rerun()