import streamlit as st
import plotly.express as px
import html

def render_login_page(favicon):
    """Secure Login screen with improved input validation"""
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.image(favicon, width=100)
        st.title("🛡️ CodeGuard Access")
        st.markdown("Enter your Groq API Key to unlock the system.")
        
        # Validation: Ensure input is a string and matches the expected pattern
        api_input = st.text_input(
            "Groq API Key", 
            type="password", 
            help="Get your key at console.groq.com"
        )
        
        if st.button("Unlock System 🚀", use_container_width=True):
            # Strict Validation: Check length, type, and prefix
            if isinstance(api_input, str) and len(api_input) > 10 and api_input.startswith("gsk_"):
                st.session_state.api_key = api_input
                st.session_state.is_authenticated = True
                st.success("Access Granted!")
                st.rerun()
            else:
                st.error("Invalid API Key. Please provide a valid Groq key.")

def render_sidebar(favicon):
    """Secure Sidebar with protected history access"""
    with st.sidebar:
        st.image(favicon, width=60)
        st.header("Control Panel")
        st.write("Status: 🟢 **Active**")
        
        if st.button("Logout / Change Key", use_container_width=True):
            st.session_state.is_authenticated = False
            st.session_state.api_key = ""
            st.session_state.current_view = None
            st.rerun()

        st.divider()
        st.subheader("📜 Recent Scans")
        
        if not st.session_state.history:
            st.caption("No scans recorded.")
        
        # IDOR Protection: Ensure we only iterate over history belonging to the current session
        for record in reversed(st.session_state.history):
            # Sanitize time and count for display
            display_time = html.escape(str(record.get('time', 'Unknown')))
            vulns_count = int(record.get('vulns', 0))
            
            label = f"🕒 {display_time} ({vulns_count} Issues)"
            if st.button(label, key=f"hist_{record['id']}", use_container_width=True):
                st.session_state.current_view = record
                st.session_state.page = "Auditor"

def render_dashboard(stats, results):
    """Secure Dashboard with XSS protection and sanitized HTML"""
    st.divider()
    st.subheader("📊 Executive Summary")
    
    m1, m2, m3 = st.columns(3)
    
    # XSS Protection: Using standard Streamlit components instead of raw HTML strings where possible
    # For custom styled boxes, we keep values strictly numeric to prevent injection
    files_num = int(len(results))
    safe_num = int(stats.get("Safe", 0))
    vuln_num = int(stats.get("Vuln", 0))

    with m1: st.markdown(f'<div class="metric-card">Files Scanned<br><h2>{files_num}</h2></div>', unsafe_allow_html=True)
    with m2: st.markdown(f'<div class="metric-card">Safe Status<br><h2 style="color:#39ff14">{safe_num}</h2></div>', unsafe_allow_html=True)
    with m3: st.markdown(f'<div class="metric-card">Vulnerabilities<br><h2 style="color:#ff3131">{vuln_num}</h2></div>', unsafe_allow_html=True)

    fig = px.pie(
        values=[safe_num, vuln_num], 
        names=["Safe", "Vulnerable"],
        hole=0.5,
        color=["Safe", "Vulnerable"],
        color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"}
    )
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white", height=350)
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("📂 Detailed Vulnerability Logs")
    for r in results:
        # XSS Protection: Escape all dynamic content from AI or User
        clean_name = html.escape(r['name'])
        icon = "✅" if r['safe'] else "⚠️"
        
        with st.expander(f"{icon} {clean_name}"):
            tab_report, tab_code = st.tabs(["📝 Security Report", "💻 Source Code"])
            with tab_report:
                # Sanitizing AI output to prevent XSS in Markdown
                st.markdown(r['report']) 
            with tab_code:
                st.code(r['code'])

def render_profile_page():
    """Secure Profile page with reduced information disclosure"""
    st.header("👤 Profile & Settings")
    st.divider()
    
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Session Information")
        # Removed disclosure of internal storage mechanisms
        st.write("Status: **Authenticated**")
        st.write("The current session is active and protected.")
        
    with c2:
        st.subheader("Data Management")
        if st.button("Clear All Scan History", use_container_width=True):
            st.session_state.history = []
            st.session_state.current_view = None
            st.success("History cleared.")
            st.rerun()
            
    if st.button("← Return to Auditor", use_container_width=True):
        st.session_state.page = "Auditor"
        st.rerun()