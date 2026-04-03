import groq
import os

def analyze_code_security(filename, content, api_key, persona="Student"):
    """
    Analyzes code content using Groq LLM with persona-specific security thresholds.
    """
    client = groq.Groq(api_key=api_key)
    
    # Define analysis thresholds based on the selected persona
    if "Student" in persona:
        # Lenient, educational approach for learners
        system_rules = (
            "You are an educational security tutor. Be encouraging and helpful. "
            "If the code has minor issues but no critical exploits, mark it as [STATUS: SAFE]. "
            "Focus on teaching best practices rather than strict enforcement."
        )
    else:
        # Strict, production-ready approach for professionals
        system_rules = (
            "You are a Senior Lead Security Auditor. Follow OWASP Top 10 strictly. "
            "If there is any potential risk, data leak, or unsafe practice, "
            "you MUST mark it as [STATUS: VULNERABLE]. Do not be lenient."
        )

    # Construct the prompt for the model
    user_prompt = f"""
    Filename: {filename}
    User Profile: {persona}
    
    Instructions:
    1. Start the response with either '[STATUS: SAFE]' or '[STATUS: VULNERABLE]'.
    2. Provide a 'Security Impact' summary.
    3. List 'Specific Findings' found in the code.
    4. Provide 'Recommended Fixes' with code examples.
    
    Source Code:
    ---
    {content}
    ---
    """

    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_rules},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3, # Low temperature for consistent security auditing
            max_tokens=2048
        )
        
        return completion.choices[0].message.content
        
    except Exception as e:
        return f"[STATUS: ERROR]\nAn error occurred during AI analysis: {str(e)}"

def get_summary_stats(results):
    """
    Calculates security metrics from a list of analysis results.
    """
    stats = {"High": 0, "Medium": 0, "Low": 0, "Safe": 0, "Vuln": 0}
    
    for r in results:
        report_upper = r['report'].upper()
        if "[STATUS: SAFE]" in report_upper:
            stats["Safe"] += 1
        else:
            stats["Vuln"] += 1
            # Categorize severity based on keywords in the report
            if "HIGH" in report_upper:
                stats["High"] += 1
            elif "MEDIUM" in report_upper:
                stats["Medium"] += 1
            else:
                stats["Low"] += 1
                
    return stats