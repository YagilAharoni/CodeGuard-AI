import zipfile
import io
import time
import logging
from fpdf import FPDF
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend

logger = logging.getLogger(__name__)

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

def sanitize_text(text):
    """
    Sanitize text to be compatible with Latin-1 encoding (standard FPDF fonts).
    Strips emojis and other non-Latin-1 characters.
    """
    if not text:
        return ""
    try:
        # Convert to string if not already
        s = str(text)
        # Encode to latin-1 while ignoring errors, then decode back
        return s.encode('latin-1', 'ignore').decode('latin-1')
    except Exception:
        return ""

def generate_pdf_report(results, stats, persona, improvement_suggestions=None, username="anonymous"):
    """
    Generates a professional PDF report using FPDF.
    Handles encoding to prevent crashes on non-Latin characters.
    """
    try:
        logger.info(f"PDF generation started - persona: {persona}, username: {username}, results type: {type(results)}, suggestions: {len(improvement_suggestions) if improvement_suggestions else 0}")
        
        # Validate input data
        if not results or not isinstance(results, dict):
            logger.error("Invalid results format provided to PDF generation")
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 20, "CodeGuard AI - Security Report", ln=True, align='C')
            pdf.set_font("Arial", "", 12)
            pdf.cell(0, 20, "Invalid scan results format.", ln=True, align='C')
            pdf_bytes = pdf.output()
            if isinstance(pdf_bytes, str):
                pdf_bytes = pdf_bytes.encode('latin-1', errors='ignore')
            return pdf_bytes
            
        if not stats:
            logger.warning("No stats provided, using defaults")
            stats = {"High": 0, "Medium": 0, "Low": 0}
        
        pdf = FPDF()

        # ─────────────────────────────────────────────────────────────────────
        # PAGE 1 — PROFESSIONAL COVER PAGE
        # ─────────────────────────────────────────────────────────────────────
        pdf.add_page()

        # Dark background
        pdf.set_fill_color(10, 12, 16)          # #0A0C10
        pdf.rect(0, 0, 210, 297, 'F')

        # Accent header bar (cyan-to-purple gradient simulation using two rects)
        pdf.set_fill_color(0, 200, 220)         # cyan
        pdf.rect(0, 0, 105, 6, 'F')
        pdf.set_fill_color(138, 43, 226)        # purple
        pdf.rect(105, 0, 105, 6, 'F')

        # Shield icon area – simple framed box
        pdf.set_fill_color(20, 25, 35)
        pdf.set_draw_color(0, 200, 220)
        pdf.set_line_width(0.8)
        pdf.rect(70, 28, 70, 70, 'FD')

        # Shield emoji / text placeholder
        pdf.set_font("Arial", "B", 36)
        pdf.set_text_color(0, 200, 220)
        pdf.set_xy(70, 42)
        pdf.cell(70, 40, "CG AI", align='C')

        # Main title
        pdf.set_font("Arial", "B", 26)
        pdf.set_text_color(220, 230, 240)
        pdf.set_xy(10, 110)
        pdf.cell(190, 14, "Security Audit Report", align='C', ln=True)

        pdf.set_font("Arial", "", 13)
        pdf.set_text_color(130, 150, 165)
        pdf.set_xy(10, 126)
        pdf.cell(190, 10, "Powered by CodeGuard AI  |  Enterprise-Grade Analysis", align='C', ln=True)

        # Divider
        pdf.set_draw_color(50, 60, 70)
        pdf.set_line_width(0.4)
        pdf.line(20, 142, 190, 142)

        # Metadata block
        meta_y = 150
        meta_items = [
            ("Scanned By", username),
            ("Analysis Persona", persona),
            ("Generated", time.strftime("%Y-%m-%d %H:%M UTC")),
            ("Overall Status", results.get("status", "UNKNOWN")),
        ]
        for label, value in meta_items:
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(0, 200, 220)
            pdf.set_xy(30, meta_y)
            pdf.cell(50, 9, sanitize_text(label) + ":", ln=False)
            pdf.set_font("Arial", "", 10)
            # Colour-code the status value
            if label == "Overall Status":
                if value == "SAFE":
                    pdf.set_text_color(50, 200, 100)
                elif value == "VULNERABLE":
                    pdf.set_text_color(239, 68, 68)
                else:
                    pdf.set_text_color(234, 179, 8)
            else:
                pdf.set_text_color(200, 210, 220)
            pdf.cell(130, 9, sanitize_text(value), ln=True)
            meta_y += 10

        # Stats summary boxes (H / M / L)
        box_y = meta_y + 10
        box_configs = [
            ("HIGH", stats.get("High", 0), (239, 68, 68)),
            ("MEDIUM", stats.get("Medium", 0), (234, 179, 8)),
            ("LOW", stats.get("Low", 0), (59, 130, 246)),
        ]
        box_x_start = 20
        box_w = 52
        box_gap = 7
        for i, (label, count, (r, g, b)) in enumerate(box_configs):
            bx = box_x_start + i * (box_w + box_gap)
            # Box background
            pdf.set_fill_color(r // 5, g // 5, b // 5)
            pdf.set_draw_color(r, g, b)
            pdf.set_line_width(0.6)
            pdf.rect(bx, box_y, box_w, 32, 'FD')
            # Count
            pdf.set_font("Arial", "B", 22)
            pdf.set_text_color(r, g, b)
            pdf.set_xy(bx, box_y + 4)
            pdf.cell(box_w, 14, str(count), align='C', ln=False)
            # Label
            pdf.set_font("Arial", "", 9)
            pdf.set_text_color(160, 170, 180)
            pdf.set_xy(bx, box_y + 20)
            pdf.cell(box_w, 8, label, align='C', ln=False)

        # Footer
        pdf.set_text_color(60, 75, 90)
        pdf.set_font("Arial", "", 8)
        pdf.set_xy(10, 280)
        pdf.cell(190, 8, "CONFIDENTIAL | CodeGuard AI Security Report | For Internal Use Only", align='C')

        # ─────────────────────────────────────────────────────────────────────
        # PAGE 2 — EXECUTIVE SUMMARY
        # ─────────────────────────────────────────────────────────────────────
        pdf.add_page()
        pdf.set_fill_color(255, 255, 255)

        # Header
        pdf.set_font("Arial", "B", 16)
        pdf.set_text_color(30, 35, 45)
        pdf.cell(0, 10, "CodeGuard AI - Security Audit Report", ln=True, align='C')
        pdf.ln(5)
        
        # Sub header meta
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(100, 110, 120)
        pdf.cell(0, 10, f"Scanned By: {username}  |  Persona: {persona}  |  Generated: {time.strftime('%Y-%m-%d %H:%M')}", ln=True)
        pdf.ln(10)

        # Executive Summary
        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(30, 35, 45)
        pdf.cell(0, 10, "1. Executive Summary", ln=True)
        pdf.set_font("Arial", "", 10)
        total_files = len(results.get("findings_by_file", {}))
        pdf.cell(0, 8, f"Total Files Analyzed: {total_files}", ln=True)
        pdf.cell(0, 8, f"Overall Status: {sanitize_text(results.get('status', 'UNKNOWN'))}", ln=True)
        pdf.cell(0, 8, f"High Risk Vulnerabilities: {stats.get('High', 0)}", ln=True)
        pdf.cell(0, 8, f"Medium Risk Vulnerabilities: {stats.get('Medium', 0)}", ln=True)
        pdf.cell(0, 8, f"Low Risk Vulnerabilities: {stats.get('Low', 0)}", ln=True)
        pdf.ln(10)

        # Vulnerability Bar Chart
        chart_success = False
        try:
            fig, ax = plt.subplots(figsize=(10, 4))
            fig.patch.set_facecolor('white')
            
            categories = ['High', 'Medium', 'Low']
            values = [stats.get('High', 0), stats.get('Medium', 0), stats.get('Low', 0)]
            colors = ['#ef4444', '#eab308', '#3b82f6']
            
            ax.bar(categories, values, color=colors, edgecolor='black', linewidth=1.5)
            ax.set_ylabel('Count', fontsize=12, fontweight='bold')
            ax.set_title('Vulnerability Distribution by Severity', fontsize=14, fontweight='bold')
            ax.grid(axis='y', alpha=0.3)
            ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
            
            for i, v in enumerate(values):
                ax.text(i, v + 0.1, str(v), ha='center', va='bottom', fontweight='bold')
            
            # Save chart to bytes
            chart_bytes = io.BytesIO()
            plt.savefig(chart_bytes, format='png', dpi=100, bbox_inches='tight')
            chart_bytes.seek(0)
            
            # Add chart to PDF
            pdf.add_page()
            pdf.set_font("Arial", "B", 12)
            pdf.set_text_color(30, 35, 45)
            pdf.cell(0, 10, "2. Vulnerability Distribution Chart", ln=True)
            pdf.ln(5)
            
            import tempfile
            import os
            temp_dir = tempfile.gettempdir()
            temp_image = os.path.join(temp_dir, "vuln_chart.png")
            with open(temp_image, 'wb') as f:
                f.write(chart_bytes.getvalue())
            
            pdf.image(temp_image, x=10, y=pdf.get_y(), w=190)
            pdf.ln(70)
            
            plt.close(fig)
            chart_success = True
            logger.info("Chart generation successful")
        except Exception as e:
            logger.error(f"Failed to generate chart: {e}")
            chart_success = False
            pdf.add_page()
            pdf.set_font("Arial", "", 10)
            pdf.cell(0, 10, f"Chart generation failed: {str(e)}", ln=True)

        # Detailed Findings by File
        pdf.add_page()
        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(30, 35, 45)
        pdf.cell(0, 10, "3. Detailed Findings by File", ln=True)
        pdf.ln(5)
        
        findings_by_file = results.get("findings_by_file", {})
        if not findings_by_file:
            pdf.set_font("Arial", "", 10)
            pdf.cell(0, 10, "No findings to display.", ln=True)
        else:
            for file_name, findings in findings_by_file.items():
                pdf.set_font("Arial", "B", 11)
                safe_name = sanitize_text(file_name)
                finding_count = len(findings)
                status = "SAFE" if finding_count == 0 else "VULNERABLE"
                pdf.cell(0, 10, f"File: {safe_name} [{status}] - {finding_count} issue{'s' if finding_count != 1 else ''}", ln=True)
                pdf.ln(3)
                
                if findings:
                    for idx, finding in enumerate(findings, 1):
                        pdf.set_font("Arial", "B", 9)
                        issue_desc = finding.get('issue_description', 'No description')
                        pdf.cell(0, 6, f"Issue {idx}: {sanitize_text(issue_desc)}", ln=True)
                        
                        pdf.set_font("Arial", "", 8)
                        # Root Problem
                        root_prob = finding.get('root_problem')
                        if root_prob:
                            pdf.set_font("Arial", "B", 8)
                            pdf.set_text_color(100, 30, 30)
                            pdf.cell(30, 5, "Root Problem:", ln=False)
                            pdf.set_font("Arial", "", 8)
                            pdf.set_text_color(30, 35, 45)
                            pdf.multi_cell(160, 5, sanitize_text(root_prob))
                        
                        # Suggested Solution
                        sug_sol = finding.get('suggested_solution')
                        if sug_sol:
                            pdf.set_font("Arial", "B", 8)
                            pdf.set_text_color(30, 100, 30)
                            pdf.cell(30, 5, "Suggested Solution:", ln=False)
                            pdf.set_font("Arial", "", 8)
                            pdf.set_text_color(30, 35, 45)
                            pdf.multi_cell(160, 5, sanitize_text(sug_sol))
                        
                        # Remediation Fix
                        fix = finding.get('suggested_fix') or finding.get('fix', 'No fix suggested')
                        pdf.set_font("Arial", "B", 8)
                        pdf.set_text_color(30, 35, 100)
                        pdf.cell(30, 5, "Remediation / Fix:", ln=False)
                        pdf.set_font("Arial", "", 8)
                        pdf.set_text_color(30, 35, 45)
                        pdf.multi_cell(160, 5, sanitize_text(fix))
                        
                        pdf.ln(2)
                
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(5)

        # Learning Recommendations for Student Persona
        if persona == "Student" and improvement_suggestions:
            logger.info(f"Adding improvement suggestions section with {len(improvement_suggestions)} suggestions")
            pdf.add_page()
            pdf.set_font("Arial", "B", 12)
            pdf.set_text_color(30, 35, 45)
            pdf.cell(0, 10, "4. Learning Recommendations & Project Improvement", ln=True)
            pdf.ln(5)
            
            pdf.set_font("Arial", "", 10)
            for idx, suggestion in enumerate(improvement_suggestions, 1):
                pdf.set_font("Arial", "B", 10)
                pdf.set_x(10)
                pdf.cell(10, 8, f"{idx}.", ln=False)
                pdf.set_font("Arial", "", 10)
                pdf.set_x(20)
                pdf.multi_cell(170, 5, sanitize_text(suggestion))
                pdf.ln(2)

        logger.info("PDF generation completed successfully")
        try:
            pdf_bytes = pdf.output()
            if isinstance(pdf_bytes, str):
                pdf_bytes = pdf_bytes.encode('latin-1', errors='ignore')
            logger.info(f"PDF generated successfully with {len(pdf_bytes)} bytes")
            return pdf_bytes
        except Exception as encode_error:
            logger.error(f"PDF output failed: {encode_error}")
            return None
        
    except Exception as e:
        logger.error(f"PDF generation failed with error: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        import traceback
        logger.error(f"PDF generation traceback: {traceback.format_exc()}")
        return None
