import zipfile
import io
import time
import streamlit as st
from fpdf import FPDF

# ... process_uploaded_files and save_to_history stay the same ...

@st.cache_data(show_spinner="Generating PDF...")
def generate_pdf_report(results, stats, persona):
    try:
        # Initialize FPDF
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "CodeGuard AI Security Report", ln=True, align='C')
        pdf.ln(5)
        
        # Metadata
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 10, f"Persona: {persona} | Date: {time.strftime('%Y-%m-%d %H:%M')}", ln=True)
        pdf.ln(10)

        # Summary Table
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 8, f"Total Files Scanned: {len(results)}", ln=True)
        pdf.cell(0, 8, f"High Risk Findings: {stats.get('High', 0)}", ln=True)
        pdf.ln(10)

        # Content details
        for r in results:
            pdf.set_font("Arial", "B", 11)
            # Encoding fix for special characters
            name = r['name'].encode('latin-1', 'ignore').decode('latin-1')
            pdf.cell(0, 10, f"File: {name}", ln=True)
            
            pdf.set_font("Arial", "", 9)
            # Cleanup AI report text for PDF compatibility
            clean_text = r['report'].encode('latin-1', 'ignore').decode('latin-1')
            pdf.multi_cell(0, 5, clean_text)
            pdf.ln(5)

        # CRITICAL: Return as a byte-string for Streamlit
        return pdf.output(dest='S').encode('latin-1')
    except Exception as e:
        # If it fails, we return None so the UI knows not to show the button
        return None