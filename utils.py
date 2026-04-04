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

def generate_pdf_report(results, stats, persona, improvement_suggestions=None):
    """
    Generates a professional PDF report using FPDF.
    Handles encoding to prevent crashes on non-Latin characters.
    """
    try:
        logger.info(f"PDF generation started - persona: {persona}, results type: {type(results)}, suggestions: {len(improvement_suggestions) if improvement_suggestions else 0}")
        
        # Validate input data
        if not results or not isinstance(results, dict):
            logger.error("Invalid results format provided to PDF generation")
            # Create a basic PDF with a message
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 20, "CodeGuard AI - Security Report", ln=True, align='C')
            pdf.set_font("Arial", "", 12)
            pdf.cell(0, 20, "Invalid scan results format.", ln=True, align='C')
            return pdf.output(dest='S').encode('utf-8', errors='ignore')
            
        if not stats:
            logger.warning("No stats provided, using defaults")
            stats = {"High": 0, "Medium": 0, "Low": 0}
        
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
        total_files = len(results.get("findings_by_file", {}))
        pdf.cell(0, 8, f"Total Files Analyzed: {total_files}", ln=True)
        pdf.cell(0, 8, f"Overall Status: {results.get('status', 'UNKNOWN')}", ln=True)
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
            
            for i, v in enumerate(values):
                ax.text(i, v + 0.1, str(v), ha='center', va='bottom', fontweight='bold')
            
            # Save chart to bytes
            chart_bytes = io.BytesIO()
            plt.savefig(chart_bytes, format='png', dpi=100, bbox_inches='tight')
            chart_bytes.seek(0)
            
            # Add chart to PDF
            pdf.add_page()
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "2. Vulnerability Distribution Chart", ln=True)
            pdf.ln(5)
            
            # Create temp directory if it doesn't exist
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
            # Continue without chart
            pdf.add_page()
            pdf.set_font("Arial", "", 10)
            pdf.cell(0, 10, f"Chart generation failed: {str(e)}", ln=True)

        # Detailed Findings by File
        pdf.add_page()
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "3. Detailed Findings by File", ln=True)
        pdf.ln(5)
        
        findings_by_file = results.get("findings_by_file", {})
        if not findings_by_file:
            pdf.set_font("Arial", "", 10)
            pdf.cell(0, 10, "No findings to display.", ln=True)
        else:
            for file_name, findings in findings_by_file.items():
                pdf.set_font("Arial", "B", 11)
                safe_name = file_name.encode('latin-1', 'ignore').decode('latin-1')
                finding_count = len(findings)
                status = "SAFE" if finding_count == 0 else "VULNERABLE"
                pdf.cell(0, 10, f"File: {safe_name} [{status}] - {finding_count} issue{'s' if finding_count != 1 else ''}", ln=True)
                pdf.ln(3)
                
                if findings:
                    for idx, finding in enumerate(findings, 1):
                        pdf.set_font("Arial", "B", 9)
                        issue_desc = finding.get('issue_description', 'No description')
                        safe_desc = issue_desc.encode('latin-1', 'ignore').decode('latin-1')
                        pdf.cell(0, 6, f"Issue {idx}: {safe_desc}", ln=True)
                        
                        pdf.set_font("Arial", "", 8)
                        suggested_fix = finding.get('suggested_fix', 'No fix suggested')
                        safe_fix = suggested_fix.encode('latin-1', 'ignore').decode('latin-1')
                        pdf.multi_cell(0, 4, f"Fix: {safe_fix}")
                        pdf.ln(2)
                
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(5)

        # Learning Recommendations for Student Persona
        if persona == "Student" and improvement_suggestions:
            logger.info(f"Adding improvement suggestions section with {len(improvement_suggestions)} suggestions")
            pdf.add_page()
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "4. Learning Recommendations & Project Improvement", ln=True)
            pdf.ln(5)
            
            pdf.set_font("Arial", "", 10)
            for idx, suggestion in enumerate(improvement_suggestions, 1):
                pdf.set_font("Arial", "B", 10)
                pdf.cell(10, 8, f"{idx}.", ln=False)
                pdf.set_font("Arial", "", 10)
                clean_suggestion = suggestion.encode('latin-1', 'ignore').decode('latin-1')
                # Calculate remaining width (200 - 10 for number - margin)
                pdf.multi_cell(0, 5, clean_suggestion, x=20)
                pdf.ln(2)

        logger.info("PDF generation completed successfully")
        # Get PDF as bytes - try different methods for reliability
        try:
            pdf_bytes = pdf.output(dest='S').encode('latin-1')
            logger.info(f"PDF generated successfully with {len(pdf_bytes)} bytes")
            return pdf_bytes
        except Exception as encode_error:
            logger.warning(f"latin-1 encoding failed: {encode_error}, trying utf-8")
            try:
                pdf_bytes = pdf.output(dest='S').encode('utf-8')
                logger.info(f"PDF generated successfully with utf-8 encoding, {len(pdf_bytes)} bytes")
                return pdf_bytes
            except Exception as utf8_error:
                logger.error(f"utf-8 encoding also failed: {utf8_error}")
                # Last resort: return raw string as bytes
                pdf_string = pdf.output(dest='S')
                pdf_bytes = pdf_string.encode('utf-8', errors='ignore')
                logger.warning(f"Using fallback encoding, {len(pdf_bytes)} bytes")
                return pdf_bytes
        
    except Exception as e:
        logger.error(f"PDF generation failed with error: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        import traceback
        logger.error(f"PDF generation traceback: {traceback.format_exc()}")
        # Returns None to let UI handle the failure gracefully
        return None