import streamlit as st
import plotly.express as px
import html
import time
from utils import generate_pdf_report

# Detailed guide for the login screen only
API_HELP_GUIDE = """
### 🔑 Step-by-Step: How to get your API Key

1. **Sign Up/Login:** Go to the [Groq Cloud Console](https://console.groq.com).
2. **Find API Keys:** On the left-hand sidebar menu, click on **"API Keys"**.
3. **Generate New Key:** Click the button **"Create API Key"**.
4. **Label Your Key:** Give it a name (e.g., "CodeGuard_AI") and click **"Submit"**.
5. **Copy the Key:** A popup will show your key. Click the **Copy** icon. 
   *(⚠️ Warning: You cannot view this key again once you close the popup!)*
6. **Activate:** Paste the key here to unlock the system.

---
*🔒 **Privacy:** Your key is processed only in-memory and is never saved.*
"""

def render_login_page(favicon):
    """Renders the gateway login screen with guide and persona selection"""
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.image(favicon, width=80) 
        st.title("🛡️ CodeGuard AI Access")
        
        user_persona = st.selectbox(
            "Select your profile:",
            ["Student (Learning/Self-Audit)", "Professional (Production/Enterprise)"]
        )
        
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
                st.rerun()
            else:
                st.error("Invalid format. Groq API keys must start with 'gsk_'.")

def render_sidebar(favicon):
    """Renders sidebar without the API guide for a cleaner look"""
    with st.sidebar:
        st.image(favicon, width=50)
        st.header("CodeGuard AI")
        st.write(f"Logged in as: **{st.session_state.get('persona', 'User')}**")
        
        if st.button("Logout / Change Key", use_container_width=True):
            st.session_state.is_authenticated = False
            st.session_state.api_key = ""
            st.session_state.current_view = None
            st.rerun()
            
        st.divider()
        st.subheader("📜 Recent Scans")
        history = st.session_state.get("history", [])
        if not history:
            st.caption("No scans recorded.")
        
        for record in reversed(history):
            label = f"🕒 {record['time']} ({record['vulns']} Vulns)"
            if st.button(label, key=f"hist_{record['id']}", use_container_width=True):
                st.session_state.current_view = record
                st.session_state.page = "Auditor"
                st.rerun()

def render_auditor_landing(hero_image):
    """Renders the landing page using either a URL or Base64 string"""
    _, col_center, _ = st.columns([1, 2, 1]) 
    with col_center:
        st.markdown("<h1 style='text-align: center;'>CodeGuard AI</h1>", unsafe_allow_html=True)
        
        st.image(hero_image, use_column_width=True)
            
        st.markdown("<h3 style='text-align: center;'>Start Your Security Audit</h3>", unsafe_allow_html=True)
        st.divider()

def render_dashboard(stats, results):
    """Renders visual analytics with Risk Level breakdown and PDF Export"""
    
    col_title, col_export = st.columns([7, 3])
    with col_title:
        st.subheader("📊 Security Analysis Breakdown")
    with col_export:
        try:
            # Generate PDF using the cached utility function
            pdf_data = generate_pdf_report(results, stats, st.session_state.persona)
            st.download_button(
                label="📥 Export Report to PDF",
                data=pdf_data,
                file_name=f"CodeGuard_AI_Report_{time.strftime('%Y%m%d')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        except Exception:
            st.error("Wait for report generation...")

    # Executive Metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Files", len(results))
    m2.metric("High Risk", stats.get("High", 0))
    m3.metric("Medium Risk", stats.get("Medium", 0))
    m4.metric("Low Risk", stats.get("Low", 0))

    # Risk Chart
    fig = px.pie(
        values=[stats.get("High", 0), stats.get("Medium", 0), stats.get("Low", 0), stats.get("Safe", 0)], 
        names=["High Risk", "Medium Risk", "Low Risk", "Safe"],
        hole=0.5,
        color=["High Risk", "Medium Risk", "Low Risk", "Safe"],
        color_discrete_map={
            "High Risk": "#ff3131", 
            "Medium Risk": "#ffaa00", 
            "Low Risk": "#39ff14", 
            "Safe": "#00ccff"
        }
    )
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white", height=350)
    fig.update_traces(hoverinfo='none')
    st.plotly_chart(fig, use_container_width=True)

    # Detailed Logs
    st.subheader("📂 Detailed Vulnerability Logs")
    for r in results:
        clean_name = html.escape(r['name'])
        report_upper = r['report'].upper()
        icon = "🔴" if "HIGH" in report_upper else "🟡" if "MEDIUM" in report_upper else "✅"
        
        with st.expander(f"{icon} {clean_name}", expanded=False):
            tab_report, tab_code = st.tabs(["📝 Security Report", "💻 Source Code"])
            with tab_report:
                st.markdown(r['report'])
            with tab_code:
                st.code(r['code'])

def render_profile_page():
    st.header("👤 Profile & Settings")
    st.divider()
    st.write(f"**Persona:** {st.session_state.get('persona', 'Not set')}")
    
    if st.button("🗑️ Clear History", use_container_width=True):
        st.session_state.history = []
        st.session_state.current_view = None
        st.rerun()
            
    if st.button("← Return", use_container_width=True):
        st.session_state.page = "Auditor"
        st.rerun()

def render_about_page():
    st.header("🛡️ About CodeGuard AI")
    st.divider()
    st.markdown("""
    **CodeGuard AI** is an advanced security auditor designed to bridge the gap between 
    development and production-ready security.
    
    * **Automated SAST:** Static Application Security Testing powered by Llama-3.
    * **Professional PDF Reports:** Get instant compliance-ready documentation.
    * **Privacy First:** We don't store your code. Everything is in-memory.
    """)
    if st.button("← Back", use_container_width=True):
        st.session_state.page = "Auditor"
        st.rerun()