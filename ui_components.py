import streamlit as st
import plotly.express as px
import html

# Step-by-step guide for API Key
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
    """Renders the gateway login screen"""
    _, col, _ = st.columns([1, 2, 1])
    with col:
        # Smaller icon as requested
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
                st.error("Invalid format. Keys must start with 'gsk_'.")

def render_sidebar(favicon):
    """Renders the sidebar with history navigation"""
    with st.sidebar:
        st.image(favicon, width=50) # Smaller sidebar icon
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
        for record in reversed(history):
            label = f"🕒 {record['time']} ({record['vulns']} Vulns)"
            if st.button(label, key=f"hist_{record['id']}", use_container_width=True):
                st.session_state.current_view = record
                st.session_state.page = "Auditor"
                st.rerun()

def render_dashboard(stats, results):
    """Renders the visual analytics and reports"""
    st.divider()
    st.subheader("📊 Security Summary")
    
    m1, m2, m3 = st.columns(3)
    files_count = int(len(results))
    safe_count = int(stats.get("Safe", 0))
    vuln_count = int(stats.get("Vuln", 0))

    with m1: st.markdown(f'<div class="metric-card">Files<br><h2>{files_count}</h2></div>', unsafe_allow_html=True)
    with m2: st.markdown(f'<div class="metric-card">Safe<br><h2 style="color:#39ff14">{safe_count}</h2></div>', unsafe_allow_html=True)
    with m3: st.markdown(f'<div class="metric-card">Vulns<br><h2 style="color:#ff3131">{vuln_count}</h2></div>', unsafe_allow_html=True)

    fig = px.pie(
        values=[safe_count, vuln_count], 
        names=["Safe", "Vulnerable"],
        hole=0.5,
        color=["Safe", "Vulnerable"],
        color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"}
    )
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="white", height=300)
    fig.update_traces(hoverinfo='none')
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("📂 Vulnerability Logs")
    for r in results:
        clean_name = html.escape(r['name'])
        icon = "✅" if r['safe'] else "⚠️"
        with st.expander(f"{icon} {clean_name}", expanded=False):
            t1, t2 = st.tabs(["Report", "Source"])
            t1.markdown(r['report'])
            t2.code(r['code'])

def render_profile_page():
    st.header("👤 Profile & Settings")
    st.divider()
    st.write(f"**Persona:** {st.session_state.get('persona', 'Not set')}")
    if st.button("🗑️ Clear History", use_container_width=True):
        st.session_state.history = []
        st.session_state.current_view = None
        st.rerun()
    if st.button("← Back", use_container_width=True):
        st.session_state.page = "Auditor"
        st.rerun()

def render_about_page():
    st.header("🛡️ About CodeGuard AI")
    st.divider()
    st.write("""
    **CodeGuard AI** is a state-of-the-art security auditor. 
    It helps developers identify risks early in the development lifecycle.
    """)
    if st.button("← Back to Auditor", use_container_width=True):
        st.session_state.page = "Auditor"
        st.rerun()