import zipfile
import io
import time
from fpdf import FPDF

def process_uploaded_files(uploaded_files):
    """Processes multiple files or ZIP archives into a list of contents"""
    files_to_scan = []
    for f in uploaded_files:
        if f.name.endswith('.zip'):
            try:
                with zipfile.ZipFile(f) as z:
                    for filename in z.namelist():
                        ext = filename.split('.')[-1].lower()
                        # Skip directories and non-code files
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
    """Saves scan results to the Streamlit session state"""
    import streamlit as st
    if "history" not in st.session_state:
        st.session_state.history = []
    
    entry = {
        "id": len(st.session_state.history),
        "time": time.strftime("%H:%M:%S"),
        "vulns": stats.get("Vuln", 0) + stats.get("High", 0) + stats.get("Medium", 0), # Sum of issues
        "stats": stats,
        "full_results": results
    }
    st.session_state.history.append(entry)

def generate_pdf_report(results, stats, persona):
    """Generates a professional PDF report from the audit results"""
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 15, "CodeGuard AI - Security Audit Report", ln=True, align='C')
    
    # Subheader
    pdf.set_font("Arial", "", 10)
    current_date = time.strftime('%Y-%m-%d %H:%M')
    pdf.cell(0, 10, f"Persona: {persona} | Generated: {current_date}", ln=True, align='C')
    pdf.ln(10)

    # Executive Summary Table
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Total Files Scanned: {len(results)}", ln=True)
    pdf.cell(0, 10, f"Safety Status: {'Issues Found' if stats.get('Vuln', 0) > 0 else 'All Clear'}", ln=True)
    pdf.ln(10)

    # Findings
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "2. Detailed Findings", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    for r in results:
        pdf.set_font("Arial", "B", 11)
        status_text = "VULNERABLE" if not r['safe'] else "SAFE"
        pdf.cell(0, 8, f"File: {r['name']} - [{status_text}]", ln=True)
        
        pdf.set_font("Arial", "", 10)
        # Cleaning characters that FPDF doesn't like
        clean_report = r['report'].encode('latin-1', 'ignore').decode('latin-1')
        clean_report = clean_report.replace('###', '').replace('**', '').replace('`', "'")
        
        pdf.multi_cell(0, 5, clean_report)
        pdf.ln(5)
        pdf.line(10, pdf.get_y(), 50, pdf.get_y())
        pdf.ln(5)

    return pdf.output()