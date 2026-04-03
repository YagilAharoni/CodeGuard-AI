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
                        ext = filename.split('.')[-1].lower()
                        # Process only code files and ignore hidden/metadata files
                        if ext in ['py', 'cpp', 'h', 'js'] and not filename.startswith('__'):
                            with z.open(filename) as internal_file:
                                content = internal_file.read().decode("utf-8", errors="ignore")
                                files_to_scan.append({
                                    "name": filename,
                                    "content": content
                                })
            except Exception as e:
                st.error(f"Error processing ZIP file {f.name}: {e}")
                continue
        else:
            try:
                content = f.read().decode("utf-8", errors="ignore")
                files_to_scan.append({
                    "name": f.name,
                    "content": content
                })
            except Exception as e:
                st.error(f"Error reading file {f.name}: {e}")
                continue
    return files_to_scan

def save_to_history(results, stats):
    """
    Saves the current scan results and statistics to the session history.
    """
    if "history" not in st.session_state:
        st.session_state.history = []
    
    # Calculate total vulnerabilities found for the label
    total_issues = stats.get("High", 0) + stats.get("Medium", 0) + stats.get("Low", 0)
    
    entry = {
        "id": len(st.session_state.history),
        "time": time.strftime("%H:%M:%S"),
        "vulns": total_issues,
        "stats": stats,
        "full_results": results
    }
    st.session_state.history.append(entry)

@st.cache_data(show_spinner="Generating security report...")
def generate_pdf_report(results, stats, persona):
    """
    Generates a professional PDF report. 
    Cached to prevent re-generation on every UI interaction.
    """
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Header Section
    pdf.set_font("Arial", "B", 22)
    pdf.set_text_color(13, 17, 23) # Dark theme color
    pdf.cell(0, 20, "CodeGuard AI - Audit Report", ln=True, align='C')
    
    pdf.set_font("Arial", "I", 10)
    pdf.set_text_color(100, 100, 100)
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    pdf.cell(0, 10, f"Persona: {persona} | Timestamp: {current_time}", ln=True, align='C')
    pdf.ln(10)

    # 1. Executive Summary
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Total Files Scanned: {len(results)}", ln=True)
    pdf.cell(0, 10, f"High Risk Issues: {stats.get('High', 0)}", ln=True)
    pdf.cell(0, 10, f"Medium Risk Issues: {stats.get('Medium', 0)}", ln=True)
    pdf.cell(0, 10, f"Low Risk Issues: {stats.get('Low', 0)}", ln=True)
    pdf.ln(10)

    # 2. Detailed File Analysis
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "2. Detailed Analysis", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    for r in results:
        # File Title
        pdf.set_font("Arial", "B", 12)
        status = "VULNERABLE" if not r['safe'] else "SAFE"
        pdf.set_text_color(200, 0, 0) if not r['safe'] else pdf.set_text_color(0, 150, 0)
        pdf.cell(0, 10, f"FILE: {r['name']} [{status}]", ln=True)
        
        # Audit Content
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(0, 0, 0)
        
        # Sanitizing text for FPDF (Standard Latin-1)
        report_text = r['report']
        report_text = report_text.replace('###', '').replace('**', '').replace('`', "'").replace('•', '-')
        # Force encoding to ignore non-latin characters that crash FPDF
        clean_text = report_text.encode('latin-1', 'ignore').decode('latin-1')
        
        pdf.multi_cell(0, 6, clean_text)
        pdf.ln(5)
        pdf.line(10, pdf.get_y(), 60, pdf.get_y())
        pdf.ln(5)

    # Output as binary string
    return pdf.output()