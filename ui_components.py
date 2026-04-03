import streamlit as st
import plotly.express as px
import html

def render_login_page(favicon):
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.image(favicon, width=100)
        st.title("🛡️ CodeGuard Access")
        
        # User Persona Selection
        user_persona = st.selectbox(
            "Select your profile:",
            ["Student (Learning/Self-Audit)", 
             "Professional (Production/Enterprise)"],
            help="Tailors the AI audit severity to your needs."
        )
        
        api_input = st.text_input("Groq API Key", type="password")
        
        if st.button("Unlock System 🚀", use_container_width=True):
            if isinstance(api_input, str) and api_input.startswith("gsk_"):
                st.session_state.api_key = api_input
                st.session_state.persona = user_persona
                st.session_state.is_authenticated = True
                st.rerun()
            else:
                st.error("Invalid Key. Must start with 'gsk_'.")

def render_sidebar(favicon):
    with st.sidebar:
        st.image(favicon, width=60)
        st.write(f"Logged in as: **{st.session_state.get('persona', 'User')}**")
        if st.button("Logout"):
            st.session_state.is_authenticated = False
            st.rerun()
        st.divider()
        st.subheader("📜 History")
        for record in reversed(st.session_state.history):
            if st.button(f"🕒 {record['time']} ({record['vulns']} Vulns)", key=f"h_{record['id']}", use_container_width=True):
                st.session_state.current_view = record

def render_dashboard(stats, results):
    st.divider()
    m1, m2, m3 = st.columns(3)
    m1.metric("Files", len(results))
    m2.metric("Safe", stats["Safe"])
    m3.metric("Vulns", stats["Vuln"])
    
    fig = px.pie(values=[stats["Safe"], stats["Vuln"]], names=["Safe", "Vuln"], hole=0.5,
                 color_discrete_map={"Safe": "#39ff14", "Vuln": "#ff3131"})
    st.plotly_chart(fig, use_container_width=True)

    for r in results:
        with st.expander(f"{'✅' if r['safe'] else '⚠️'} {html.escape(r['name'])}"):
            t1, t2 = st.tabs(["Report", "Code"])
            t1.markdown(r['report'])
            t2.code(r['code'])