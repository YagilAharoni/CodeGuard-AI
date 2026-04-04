import groq
import os

def analyze_code_security(filename, content, api_key, persona="Student"):
    """
    Analyzes code security with specific thresholds for Students vs Professionals.
    """
    client = groq.Groq(api_key=api_key)
    
    if "Student" in persona:
        # Educational and lenient logic
        system_rules = (
            "You are a helpful Security Tutor for students. "
            "Your goal is to encourage learning. If the code has minor issues, "
            "best practice violations, or non-critical bugs, mark it as [STATUS: SAFE]. "
            "However, you MUST still list these minor issues in your findings as 'Areas for Improvement'. "
            "Only mark as [STATUS: VULNERABLE] if there is a severe, high-risk security exploit."
        )
        current_temp = 0.3
    else:
        # Strict and ruthless professional logic
        system_rules = (
            "You are a Senior Lead Cyber-Security Auditor. Your job is to be RUTHLESS. "
            "You do not give the benefit of the doubt. If there is even a minor risk, "
            "lack of input validation, or hardcoded sensitive data, you MUST mark it as [STATUS: VULNERABLE]. "
            "A Professional is expected to write production-grade, bulletproof code."
        )
        current_temp = 0.1

    user_prompt = f"""
    Analyze the following file for security vulnerabilities.
    
    File: {filename}
    Persona Context: {persona}
    
    Report Requirements:
    1. Start your response with either '[STATUS: SAFE]' or '[STATUS: VULNERABLE]'.
    2. Provide a 'Security Summary'.
    3. List 'Vulnerability Details' (if any).
    4. Provide 'Recommended Code Fixes'.
    
    Code Content:
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
            temperature=current_temp,
            max_tokens=1028 
        )
        
        return completion.choices[0].message.content
        
    except Exception as e:
        return f"[STATUS: ERROR]\nFailed to communicate with AI: {str(e)}"

def get_summary_stats(results):
    """
    Parses results to generate overall statistics.
    """
    stats = {"High": 0, "Medium": 0, "Low": 0, "Safe": 0, "Vuln": 0}
    
    for r in results:
        report_text = r['report'].upper()
        if "[STATUS: SAFE]" in report_text:
            stats["Safe"] += 1
        else:
            stats["Vuln"] += 1
            if "HIGH" in report_text: stats["High"] += 1
            elif "MEDIUM" in report_text: stats["Medium"] += 1
            else: stats["Low"] += 1
                
    return stats