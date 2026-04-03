import streamlit as st
import plotly.express as px
import html
import time
from utils import generate_pdf_report  # Ensure this function exists in utils.py

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
        
        # Guide is visible here during login only
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

def render_dashboard(stats, results):
    """Renders visual analytics with Risk Level breakdown and PDF Export"""
    
    # Header Row with Export Button
    col_title, col_export = st.columns([7, 3])
    with col_title:
        st.subheader("📊 Security Analysis Breakdown")
    with col_export:
        # Generate PDF report on the fly
        try:
            pdf_data = generate_pdf_report(results, stats, st.session_state.persona)
            st.download_button(
                label="📥 Export Report to PDF",
                data=pdf_data,
                file_name=f"CodeGuard_AI_Report_{time.strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        except Exception as e:
            st.error("PDF engine initialization...")

    # Calculate Risk Levels from reports
    risk_counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in results:
        report_text = r['report'].upper()
        if "HIGH" in report_text: risk_counts["High"] += 1
        elif "MEDIUM" in report_text: risk_counts["Medium"] += 1
        elif "LOW" in report_text: risk_counts["Low"] += 1

    # Executive Metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Files Scanned", len(results))
    m2.metric("High Risk", risk_counts["High"], delta_color="inverse")
    m3.metric("Medium Risk", risk_counts["Medium"])
    m4.metric("Low Risk", risk_counts["Low"])

    # Risk Chart - Clean Look (No hover labels)
    fig = px.pie(
        values=[risk_counts["High"], risk_counts["Medium"], risk_counts["Low"], stats.get("Safe", 0)], 
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
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white", height=350, margin=dict(t=20, b=20, l=0, r=0))
    fig.update_traces(hoverinfo='none', hovertemplate=None)
    st.plotly_chart(fig, use_container_width=True)

    # Detailed Logs - All collapsed by default
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
    """Renders clean profile settings"""
    st.header("👤 Profile & Settings")
    st.divider()
    
    st.write(f"**Persona:** {st.session_state.get('persona', 'Not set')}")
    st.write("**Security Level:** Active Session (Encrypted Memory)")
    
    st.divider()
    if st.button("🗑️ Clear All Session History", use_container_width=True):
        st.session_state.history = []
        st.session_state.current_view = None
        st.success("History cleared.")
        st.rerun()
            
    if st.button("← Return to Auditor", use_container_width=True):
        st.session_state.page = "Auditor"
        st.rerun()

def render_about_page():
    """Renders application overview and value proposition"""
    st.header("🛡️ About CodeGuard AI")
    st.divider()
    
    st.markdown("""
    ### Secure Your Code with Intelligence
    **CodeGuard AI** is a specialized security auditing tool built for modern developers. 
    By leveraging Large Language Models (LLMs), it performs deep static analysis to uncover 
    vulnerabilities that traditional regex-based scanners might miss.

    #### Why use CodeGuard AI?
    * **Automated Risk Assessment:** Instant categorization of High, Medium, and Low risks.
    * **Educational Context:** Understand not just *what* is wrong, but *how* to fix it.
    * **Privacy First:** Your code and API keys are processed in-memory and never stored on our disks.
    * **Exportable Reports:** Professional PDF exports for compliance and team reviews.
    """)
    
    if st.button("← Back to Auditor", use_container_width=True):
        st.session_state.page = "Auditor"
        st.rerun()