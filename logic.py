import os
from groq import Groq

def analyze_code_security(file_name, code_content, api_key):
    """
    Context-aware security auditor. Adjusts severity based on code purpose.
    """
    try:
        client = Groq(api_key=api_key)
        
        # New Smart Prompt
        system_prompt = f"""
        You are a Senior Security Auditor. 
        
        STEP 1: Identify the PURPOSE and CONTEXT of the file '{file_name}'.
        - If the code is a simple utility (e.g., calculator, basic exercise, hello world), be lenient. Focus only on critical crashes or extreme leaks.
        - If the code handles data, networking, memory management (C++), or user input, perform a DEEP security audit.

        STEP 2: Based on the context, analyze the code.
        RULES:
        1. Start your response with exactly: [STATUS: SAFE] or [STATUS: VULNERABLE].
        2. Provide a 'Context Assessment' line explaining what you think this code does.
        3. List issues with Severity (Low/Med/High).
        4. Provide brief English fixes.
        
        All analysis must be in professional English.
        """
        
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Code Content:\n\n{code_content}"}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.2
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        return f"API Error: {str(e)}"