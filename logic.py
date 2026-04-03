from groq import Groq
import streamlit as st

def analyze_code_security(file_name, code_content, api_key):
    persona = st.session_state.get("persona", "Student")
    severity_context = "Educational focus." if "Student" in persona else "Strict enterprise standards."
    
    try:
        client = Groq(api_key=api_key)
        # Updated Prompt to force Risk Levels
        system_prompt = (
            f"You are a Senior Security Auditor for a {persona}. {severity_context} "
            f"Analyze '{file_name}'. You MUST categorize findings into: HIGH, MEDIUM, or LOW risk. "
            "Start your response with [STATUS: SAFE] or [STATUS: VULNERABLE]. "
            "If vulnerable, list each issue with its RISK LEVEL clearly labeled."
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