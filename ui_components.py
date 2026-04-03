import streamlit as st
import plotly.express as px
import html

# Detailed help text for the API Key
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
    """Renders the gateway login screen"""
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.image(favicon, width=100)
        st.title("🛡️ CodeGuard Access")
        st.markdown("Please identify yourself and enter your API Key.")
        
        user_persona = st.selectbox(
            "Select your profile:",
            ["Student (Learning/Self-Audit)", "Professional (Production/Enterprise)"]
        )
        
        # Restored the detailed help guide here
        api_input = st.text_input(
            "Groq API Key", 
            type="password",
            help=API_HELP_GUIDE
        )
        
        if st.button("Unlock System 🚀", use_container_width=True):
            if api_input.startswith("gsk_"):
                st.session_state.api_key = api_input
                st.session_state.persona = user_persona
                st.session_state.is_authenticated = True
                st.rerun()
            else:
                st.error("Invalid format. Keys must start with 'gsk_'.")

def render_sidebar(favicon):
    """Renders the sidebar with history and the detailed tooltip"""
    with st.sidebar:
        st.image(favicon, width=60)
        st.write(f"Logged in as: **{st.session_state.get('persona', 'User')}**")
        
        # Redundant but helpful: allows changing key from sidebar with the guide
        st.text_input("Current API Key", value="********", type="password", help=API_HELP_GUIDE, disabled=True)
        
        if st.button("Logout"):
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
            if st.button(f"🕒 {record['time']} ({record['vulns']} Vulns)", key=f"h_{record['id']}", use_container_width=True):
                st.session_state.current_view = record
                st.rerun()

def render_dashboard(stats, results):
    """Renders the visual analytics and detailed vulnerability reports"""
    st.divider()
    st.subheader("📊 Executive Summary")
    
    m1, m2, m3 = st.columns(3)
    m1.metric("Files", len(results))
    m2.metric("Safe", stats.get("Safe", 0))
    m3.metric("Vulns", stats.get("Vuln", 0))

    fig = px.pie(
        values=[stats.get("Safe", 0), stats.get("Vuln", 0)], 
        names=["Safe", "Vulnerable"],
        hole=0.5,
        color=["Safe", "Vulnerable"],
        color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"}
    )
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white", height=350)
    st.plotly_chart(fig, use_container_width=True)

    for r in results:
        icon = "✅" if r['safe'] else "⚠️"
        with st.expander(f"{icon} {html.escape(r['name'])}"):
            st.markdown(r['report'])