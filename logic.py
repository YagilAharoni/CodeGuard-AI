import os
import logging
from groq import Groq

# Configure logging for error tracking
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_code_security(file_name, code_content, api_key):
    """Analyzes code security using the Groq AI API"""
    try:
        client = Groq(api_key=api_key)
        
        # AI Model Instructions
        system_instructions = (
            f"You are an Elite Cyber Security Auditor. Analyze the file '{file_name}'. "
            "Identify vulnerabilities and provide a 'Suggested Fix' section with code snippets. "
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
        logger.error(f"Error in analyze_code_security: {e}")
        return f"### ❌ Analysis Error: {str(e)}"