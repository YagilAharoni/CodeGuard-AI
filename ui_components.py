import streamlit as st
import plotly.express as px

def render_dashboard(stats, results):
    """Renders the executive summary and detailed report."""
    st.divider()
    st.subheader("📊 Executive Security Summary")
    
    m1, m2, m3 = st.columns(3)
    m1.metric("Files Scanned", len(results))
    m2.metric("Safe Status", stats["Safe"])
    m3.metric("Vulnerabilities", stats["Vuln"])

    fig = px.pie(
        values=[stats["Safe"], stats["Vuln"]], 
        names=["Safe", "Vulnerable"],
        hole=0.5,
        color=["Safe", "Vulnerable"],
        color_discrete_map={"Safe": "#39ff14", "Vulnerable": "#ff3131"}
    )
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("📂 Detailed Vulnerability Logs")
    for r in results:
        icon = "✅" if r["safe"] else "⚠️"
        with st.expander(f"{icon} {r['name']}"):
            tab_report, tab_code = st.tabs(["📝 Security Report", "💻 Source Code"])
            with tab_report:
                st.markdown(r["report"])
            with tab_code:
                st.code(r["code"])