from fpdf import FPDF
import io

def generate_pdf_report(results, stats, persona):
    pdf = FPDF()
    pdf.add_page()
    
    # Header
    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 10, "CodeGuard AI - Security Audit Report", ln=True, align='C')
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 10, f"Generated for: {persona} | Date: {time.strftime('%Y-%m-%d %H:%M')}", ln=True, align='C')
    pdf.ln(10)

    # Summary Table
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Total Files Scanned: {len(results)}", ln=True)
    pdf.cell(0, 10, f"Safe Files: {stats.get('Safe', 0)}", ln=True)
    pdf.cell(0, 10, f"Vulnerabilities Found: {stats.get('Vuln', 0)}", ln=True)
    pdf.ln(10)

    # Detailed Results
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Detailed Findings", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    for r in results:
        pdf.set_font("Arial", "B", 12)
        status = "SAFE" if r['safe'] else "VULNERABLE"
        pdf.cell(0, 10, f"File: {r['name']} [{status}]", ln=True)
        
        pdf.set_font("Arial", "", 10)
        # We use multi_cell for long AI reports
        pdf.multi_cell(0, 5, r['report'].replace('###', '').replace('**', ''))
        pdf.ln(5)
        pdf.line(10, pdf.get_y(), 100, pdf.get_y())
        pdf.ln(5)

    # Return as bytes
    return pdf.output()