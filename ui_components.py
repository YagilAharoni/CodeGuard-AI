import streamlit as st
import plotly.express as px

def render_sidebar(favicon):
    """Renders the sidebar with API input and scan history."""
    with st.sidebar:
        st.image(favicon, width=60)
        st.header("Control Panel")
        
        # המדריך בסימן השאלה חזר לכאן
        st.session_state.api_key = st.text_input(
            "Groq API Key", 
            value=st.session_state.api_key, 
            type="password",
            help="""
            ### 🔑 How to get your API Key:
            1. Go to [console.groq.com](https://console.groq.com/keys)
            2. Click 'Create API Key'.
            3. Copy and paste it here.
            *Your key is kept only in session memory.*
            """
        )
        
        st.divider()
        st.subheader("📜 Recent Scans")
        if not st.session_state.history:
            st.caption("No scans yet.")
        for record in reversed(st.session_state.history):
            if st.button(f"🕒 {record['time']} ({record['vulns']} Vulns)", key=f"hist_{record['id']}", use_container_width=True):
                st.session_state.current_view = record
                st.session_state.page = "Auditor"

def render_dashboard(stats, results):
    """Renders the executive summary and detailed report."""
    st.divider()
    st.subheader("📊 Executive Security Summary")
    
    m1, m2, m3 = st.columns(3)
    with m1: st.markdown(f'<div class="metric-card">Files Scanned<br><h2>{len(results)}</h2></div>', unsafe_allow_html=True)
    with m2: st.markdown(f'<div class="metric-card">Safe Status<br><h2 style="color:#39ff14">{stats["Safe"]}</h2></div>', unsafe_allow_html=True)
    with m3: st.markdown(f'<div class="metric-card">Vulnerabilities<br><h2 style="color:#ff3131">{stats.get("Vuln", 0)}</h2></div>', unsafe_allow_html=True)

    fig = px.pie(
        values=[stats["Safe"], stats.get("Vuln", 0)], 
        names=["Safe", "Vulnerable"],
        hole=0.5,
        color=["Safe", "Vulnerable"],
        color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"}
    )
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white", height=350)
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("📂 Detailed Vulnerability Logs")
    for r in results:
        icon = "✅" if r["safe"] else "⚠️"
        with st.expander(f"{icon} {r['name']}"):
            tab_report, tab_code = st.tabs(["📝 Security Report", "💻 Source Code"])
            with tab_report:
                st.markdown(r["report"])
            with tab_code:
                st.code(r["code"])

def render_profile_page():
    """Renders the profile view with settings and help."""
    st.header("👤 User Profile & Settings")
    st.divider()
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Configuration Guide")
        st.markdown("""
        To use CodeGuard, you need a **Groq API Key**:
        1. Visit the [Groq Console](https://console.groq.com/keys).
        2. Generate a new API key.
        3. Paste it in the sidebar or the field on the right.
        """)
    
    with col2:
        st.subheader("Session Actions")
        if st.button("Clear Scan History", use_container_width=True):
            st.session_state.history = []
            st.session_state.current_view = None
            st.success("History cleared!")
            st.rerun()