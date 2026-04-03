import streamlit as st
import plotly.express as px
import html

# Professional Guide for API Key Generation
API_HELP_GUIDE = """
### 🔑 Step-by-Step: How to get your API Key

1. **Sign Up/Login:** Go to the [Groq Cloud Console](https://console.groq.com).
2. **Find API Keys:** On the left-hand sidebar menu, click on **"API Keys"**.
3. **Generate New Key:** Click the button **"Create API Key"**.
4. **Label Your Key:** Give it a name (e.g., "CodeGuard_Project") and click **"Submit"**.
5. **Copy the Key:** A popup will show your key. Click the **Copy** icon. 
   *(⚠️ Warning: You cannot view this key again once you close the popup!)*
6. **Activate:** Paste the key here to unlock the system.

---
*🔒 **Privacy:** Your key is processed only in-memory and is never saved on our servers.*
"""

def render_login_page(favicon):
    """Renders the gateway login screen with Persona selection"""
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.image(favicon, width=100)
        st.title("🛡️ CodeGuard Access")
        st.markdown("Please identify yourself and enter your API Key to proceed.")
        
        # User Persona Selection for tailored auditing
        user_persona = st.selectbox(
            "Select your profile:",
            ["Student (Learning/Self-Audit)", "Professional (Production/Enterprise)"],
            help="This helps the AI determine the severity and educational depth of the report."
        )
        
        # API Key input with the detailed guide
        api_input = st.text_input(
            "Groq API Key", 
            type="password",
            help=API_HELP_GUIDE
        )
        
        if st.button("Unlock System 🚀", use_container_width=True):
            if isinstance(api_input, str) and api_input.startswith("gsk_"):
                st.session_state.api_key = api_input
                st.session_state.persona = user_persona
                st.session_state.is_authenticated = True
                st.success(f"Access Granted as {user_persona}")
                st.rerun()
            else:
                st.error("Invalid format. Groq API keys must start with 'gsk_'.")

def render_sidebar(favicon):
    """Renders the sidebar with history navigation and the API guide"""
    with st.sidebar:
        st.image(favicon, width=60)
        st.header("Control Panel")
        st.write(f"Logged in as: **{st.session_state.get('persona', 'User')}**")
        
        # Tooltip available in sidebar as well for reference
        st.info("Hover over the '?' in input fields for the API Guide.")
        st.text_input("Current Key Status", value="Active Session", help=API_HELP_GUIDE, disabled=True)
        
        if st.button("Logout / Change Key", use_container_width=True):
            st.session_state.is_authenticated = False
            st.session_state.api_key = ""
            st.session_state.current_view = None
            st.rerun()
            
        st.divider()
        st.subheader("📜 Recent Scans")
        history = st.session_state.get("history", [])
        if not history:
            st.caption("No scans recorded in this session.")
        
        for record in reversed(history):
            # IDOR Protection: Displaying sanitized history keys
            label = f"🕒 {record['time']} ({record['vulns']} Vulns)"
            if st.button(label, key=f"hist_{record['id']}", use_container_width=True):
                st.session_state.current_view = record
                st.session_state.page = "Auditor"
                st.rerun()

def render_dashboard(stats, results):
    """Renders the visual analytics and detailed vulnerability reports"""
    st.divider()
    st.subheader("📊 Executive Security Summary")
    
    # Summary Metrics with XSS protection (converting to safe types)
    m1, m2, m3 = st.columns(3)
    files_count = int(len(results))
    safe_count = int(stats.get("Safe", 0))
    vuln_count = int(stats.get("Vuln", 0))

    with m1: st.markdown(f'<div class="metric-card">Files Scanned<br><h2>{files_count}</h2></div>', unsafe_allow_html=True)
    with m2: st.markdown(f'<div class="metric-card">Safe Status<br><h2 style="color:#39ff14">{safe_count}</h2></div>', unsafe_allow_html=True)
    with m3: st.markdown(f'<div class="metric-card">Vulnerabilities<br><h2 style="color:#ff3131">{vuln_count}</h2></div>', unsafe_allow_html=True)

    # Risk Distribution Chart
    fig = px.pie(
        values=[safe_count, vuln_count], 
        names=["Safe", "Vulnerable"],
        hole=0.5,
        color=["Safe", "Vulnerable"],
        color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"}
    )
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white", height=350)
    st.plotly_chart(fig, use_container_width=True)

    # Detailed File Breakdown
    st.subheader("📂 Detailed Vulnerability Logs")
    for r in results:
        clean_name = html.escape(r['name'])
        icon = "✅" if r['safe'] else "⚠️"
        with st.expander(f"{icon} {clean_name}", expanded=not r['safe']):
            tab_report, tab_code = st.tabs(["📝 Security Report", "💻 Source Code"])
            with tab_report:
                st.markdown(r['report'])
            with tab_code:
                st.code(r['code'])

def render_profile_page():
    """Renders the user profile and session management settings"""
    st.header("👤 Profile & Session Settings")
    st.divider()
    
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Session Information")
        st.write(f"**Persona:** {st.session_state.get('persona', 'Not set')}")
        st.write("**Security Status:** Authenticated Session")
        st.write("API Keys are held in volatile memory and cleared on logout.")
        
    with c2:
        st.subheader("Data Management")
        if st.button("🗑️ Clear All History", use_container_width=True):
            st.session_state.history = []
            st.session_state.current_view = None
            st.success("History cleared successfully!")
            st.rerun()
            
    if st.button("← Return to Auditor", use_container_width=True):
        st.session_state.page = "Auditor"
        st.rerun()