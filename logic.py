from groq import Groq
import streamlit as st

def analyze_code_security(file_name, code_content, api_key):
    persona = st.session_state.get("persona", "Student")
    
    # Adjust severity based on persona
    severity_context = "Focus on educational fixes." if "Student" in persona else "Be extremely strict for production."
    
    try:
        client = Groq(api_key=api_key)
        system_prompt = (
            f"You are a Senior Security Auditor. User Profile: {persona}. {severity_context} "
            f"Analyze '{file_name}'. Start with [STATUS: SAFE] or [STATUS: VULNERABLE]."
        )
        
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": code_content}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.2
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"