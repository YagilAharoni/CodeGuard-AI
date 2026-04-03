import streamlit as st
import plotly.express as px
import html

def render_login_page(favicon):
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.image(favicon, width=100)
        st.title("🛡️ CodeGuard Access")
        
        user_persona = st.selectbox(
            "Select your profile:",
            ["Student (Learning/Self-Audit)", "Professional (Production/Enterprise)"]
        )
        
        api_input = st.text_input(
            "Groq API Key", 
            type="password",
            help="""
            1. Go to console.groq.com
            2. Click 'API Keys' -> 'Create API Key'
            3. Copy and paste it here.
            """
        )
        
        if st.button("Unlock System 🚀", use_container_width=True):
            if api_input.startswith("gsk_"):
                st.session_state.api_key = api_input
                st.session_state.persona = user_persona
                st.session_state.is_authenticated = True
                st.rerun()
            else:
                st.error("Invalid Key format.")

def render_sidebar(favicon):
    with st.sidebar:
        st.image(favicon, width=60)
        st.write(f"Logged in as: **{st.session_state.get('persona', 'User')}**")
        if st.button("Logout"):
            st.session_state.is_authenticated = False
            st.session_state.api_key = ""
            st.rerun()
        st.divider()
        st.subheader("📜 History")
        for record in reversed(st.session_state.get("history", [])):
            if st.button(f"🕒 {record['time']} ({record['vulns']} Vulns)", key=f"h_{record['id']}", use_container_width=True):
                st.session_state.current_view = record

def render_dashboard(stats, results):
    st.divider()
    m1, m2, m3 = st.columns(3)
    m1.metric("Files", len(results))
    m2.metric("Safe", stats.get("Safe", 0))
    m3.metric("Vulns", stats.get("Vuln", 0))
    
    fig = px.pie(values=[stats.get("Safe", 0), stats.get("Vuln", 0)], 
                 names=["Safe", "Vulnerable"], hole=0.5,
                 color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"})
    st.plotly_chart(fig, use_container_width=True)

    for r in results:
        with st.expander(f"{'✅' if r['safe'] else '⚠️'} {html.escape(r['name'])}"):
            st.markdown(r['report'])