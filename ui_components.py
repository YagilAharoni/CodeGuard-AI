import streamlit as st
import plotly.express as px
import html

def render_login_page(favicon):
    """Secure Login screen with User Persona selection"""
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.image(favicon, width=100)
        st.title("🛡️ CodeGuard Access")
        st.markdown("### Welcome! Please identify yourself")
        
        # New Feature: User Persona Selection
        user_persona = st.selectbox(
            "Who are you?",
            ["Student (Self-Audit / Learning)", 
             "Independent Developer (Personal Projects)", 
             "Enterprise Developer (Production Code)"],
            help="This helps us tailor the security insights to your specific needs."
        )
        
        st.divider()
        
        api_input = st.text_input(
            "Groq API Key", 
            type="password", 
            help="Get your key at console.groq.com"
        )
        
        if st.button("Unlock System 🚀", use_container_width=True):
            if isinstance(api_input, str) and len(api_input) > 10 and api_input.startswith("gsk_"):
                st.session_state.api_key = api_input
                st.session_state.is_authenticated = True
                st.session_state.persona = user_persona # Store the selected persona
                st.success(f"Access Granted as {user_persona}!")
                st.rerun()
            else:
                st.error("Invalid API Key. Please provide a valid Groq key.")
        
        st.info("💡 Need a key? [Groq Console](https://console.groq.com/keys)")

# Rest of the functions stay the same, but you can now use st.session_state.persona anywhere