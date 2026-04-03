import os
import logging
from groq import Groq
from typing import Optional

# Setup logging for better error tracking (Low Severity fix)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_code_security(file_name: str, code_content: str, api_key: Optional[str] = None) -> str:
    """
    Advanced security auditor with robust error handling and input validation.
    """
    
    # 1. Input Validation (Medium Severity fix)
    if not file_name or not isinstance(file_name, str):
        return "### ❌ Error: Invalid or empty file name provided."
    
    if not code_content or len(code_content.strip()) < 10:
        return "### ❌ Error: Code content is too short or empty to analyze."

    # 2. Secure Key Management (High Severity fix)
    # Priority: Function argument -> Environment Variable -> Error
    final_api_key = api_key or os.environ.get("GROQ_API_KEY")
    
    if not final_api_key:
        logger.error("API Key missing in both argument and environment.")
        return "### ❌ Error: Groq API Key is not configured."

    try:
        client = Groq(api_key=final_api_key)
        
        # 3. Managed System Prompt (Low Severity fix - using structured sections)
        context_instructions = f"Analyze the purpose of '{file_name}'."
        audit_rules = (
            "Detect vulnerabilities (Buffer Overflow, SQLi, etc.). "
            "For each issue, provide a 'Suggested Fix' with a code snippet."
        )
        format_rules = "Start with [STATUS: SAFE] or [STATUS: VULNERABLE]. Use Markdown."
        
        full_system_prompt = f"{context_instructions} {audit_rules} {format_rules}"

        # 4. API Request with Error Checking (Medium Severity fix)
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": full_system_prompt},
                {"role": "user", "content": f"Audit this code:\n\n{code_content}"}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.2
        )

        # Validate response structure
        if not response.choices or not response.choices[0].message.content:
            return "### ❌ Error: API returned an empty response."

        return response.choices[0].message.content

    # 5. Specific Exception Handling (High Severity fix)
    except ConnectionError:
        logger.error("Network connection to Groq failed.")
        return "### ❌ Network Error: Could not reach the security agents. Check your internet."
    except Exception as e:
        # Log the actual error for the developer, but return a clean message to the user
        logger.exception(f"Unexpected error during audit of {file_name}")
        return f"### ❌ System Error: An internal error occurred during analysis."