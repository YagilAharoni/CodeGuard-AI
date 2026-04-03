def analyze_code_security(file_name, code_content, api_key):
    # Fetch persona from session state
    persona = st.session_state.get("persona", "General Developer")
    
    try:
        client = Groq(api_key=api_key)
        
        # Tailored Instructions based on Persona
        persona_context = ""
        if "Student" in persona:
            persona_context = "The user is a Student. Provide educational explanations and focus on best practices."
        elif "Enterprise" in persona:
            persona_context = "The user is an Enterprise Developer. Be extremely strict, focus on production security, OWASP Top 10, and zero-trust."
        
        system_instructions = (
            f"You are an Elite Cyber Security Auditor. {persona_context} "
            f"Analyze the file '{file_name}'. Identify vulnerabilities and provide a 'Suggested Fix'. "
            "Start with [STATUS: SAFE] or [STATUS: VULNERABLE]. Professional English only."
        )

        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_instructions},
                {"role": "user", "content": f"Audit this code:\n\n{code_content}"}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.2
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"### ❌ Analysis Error: {str(e)}"