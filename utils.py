import zipfile
import io
import time
import streamlit as st
from fpdf import FPDF

def process_uploaded_files(uploaded_files):
    """
    Processes uploaded files (individual or ZIP) and extracts their content.
    Returns a list of dictionaries with 'name' and 'content'.
    """
    files_to_scan = []
    for f in uploaded_files:
        if f.name.endswith('.zip'):
            try:
                with zipfile.ZipFile(f) as z:
                    for filename in z.namelist():
                        # Only scan supported source files
                        ext = filename.split('.')[-1].lower()
                        if ext in ['py', 'cpp', 'h', 'js'] and not filename.startswith('__'):
                            with z.open(filename) as internal_file:
                                files_to_scan.append({
                                    "name": filename,
                                    "content": internal_file.read().decode("utf-8", errors="ignore")
                                })
            except Exception:
                continue
        else:
            files_to_scan.append({
                "name": f.name,
                "content": f.read().decode("utf-8", errors="ignore")
            })
    return files_to_scan

def save_to_history(results, stats):
    """
    Saves the current scan results into the session history.
    """
    if "history" not in st.session_state:
        st.session_state.history = []
    
    entry = {
        "id": len(st.session_state.history),
        "time": time.strftime("%H:%M:%S"),
        "vulns": stats.get("High", 0) + stats.get("Medium", 0) + stats.get("Low", 0),
        "stats": stats,
        "full_results": results
    }
    st.session_state.history.append(entry)

@st.cache_data(show_spinner="Generating PDF Report...")
def generate_pdf_report(results, stats, persona):
    """
    Generates a professional PDF report using FPDF.
    Handles encoding to prevent crashes on non-Latin characters.
    """
    try:
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "CodeGuard AI - Security Audit Report", ln=True, align='C')
        pdf.ln(5)
        
        # Meta Info
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 10, f"Analysis Persona: {persona} | Generated: {time.strftime('%Y-%m-%d %H:%M')}", ln=True)
        pdf.ln(10)

        # Executive Summary
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "1. Executive Summary", ln=True)
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 8, f"Total Files Analyzed: {len(results)}", ln=True)
        pdf.cell(0, 8, f"High Risk Vulnerabilities: {stats.get('High', 0)}", ln=True)
        pdf.cell(0, 8, f"Medium Risk Vulnerabilities: {stats.get('Medium', 0)}", ln=True)
        pdf.ln(10)

        # Detailed Findings
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "2. Detailed Findings", ln=True)
        
        for r in results:
            pdf.set_font("Arial", "B", 11)
            # Ensure filenames are encoded for PDF safety
            safe_name = r['name'].encode('latin-1', 'ignore').decode('latin-1')
            status = "VULNERABLE" if not r['safe'] else "SAFE"
            pdf.cell(0, 10, f"File: {safe_name} [%s]" % status, ln=True)
            
            pdf.set_font("Arial", "", 9)
            # Strip problematic characters from AI report
            clean_report = r['report'].encode('latin-1', 'ignore').decode('latin-1')
            pdf.multi_cell(0, 5, clean_report)
            pdf.ln(5)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)

        # CRITICAL: Return as bytes directly for Streamlit download_button
        return pdf.output(dest='S').encode('latin-1')
        
    except Exception:
        # Returns None to let UI handle the failure gracefully
        return None