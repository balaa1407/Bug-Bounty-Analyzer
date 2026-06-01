import os

import pandas as pd
import requests
import streamlit as st

from app.config import settings
from app.security import verify_password

API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000")

st.set_page_config(page_title="Bug Bounty Analyzer", layout="wide")

# Inject premium dark theme styling
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
    
    html, body, [class*="css"], .stApp {
        font-family: 'Outfit', sans-serif;
    }
    
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Outfit', sans-serif;
        font-weight: 700 !important;
        letter-spacing: -0.02em;
    }
    
    /* Premium glassmorphism metrics container */
    div[data-testid="stMetric"] {
        background: rgba(26, 28, 35, 0.65);
        border: 1px solid rgba(255, 255, 255, 0.05);
        padding: 18px 24px;
        border-radius: 12px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2);
        backdrop-filter: blur(4px);
        -webkit-backdrop-filter: blur(4px);
        transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
    }
    
    div[data-testid="stMetric"]:hover {
        transform: translateY(-4px);
        border-color: rgba(255, 255, 255, 0.15);
        box-shadow: 0 12px 40px 0 rgba(0, 0, 0, 0.3);
    }
    
    /* Custom button styling */
    .stButton>button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        transition: all 0.2s ease !important;
    }
    
    .stButton>button:hover {
        transform: scale(1.02);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Bug Bounty Vulnerability Report Analyzer")
st.caption("Single-page workflow: reporter upload + admin-only results panel")


@st.cache_data(ttl=20)
def fetch_summary():
    response = requests.get(f"{API_BASE_URL}/analytics/summary", timeout=10)
    response.raise_for_status()
    return response.json()


@st.cache_data(ttl=20)
def fetch_reports(skip: int = 0, limit: int = 50, severity: str | None = None):
    url = f"{API_BASE_URL}/reports?skip={skip}&limit={limit}"
    if severity and severity != "All":
        url += f"&severity={severity}"
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.json().get("items", [])


def submit_report(pdf_file, screenshot1, screenshot2):
    files = {
        "pdf": (pdf_file.name, pdf_file.getvalue(), "application/pdf"),
        "screenshot1": (screenshot1.name, screenshot1.getvalue(), screenshot1.type),
        "screenshot2": (screenshot2.name, screenshot2.getvalue(), screenshot2.type),
    }
    response = requests.post(f"{API_BASE_URL}/analyze", files=files, timeout=90)
    if response.status_code >= 400:
        raise RuntimeError(response.text)
    return response.json()


if "is_admin" not in st.session_state:
    st.session_state["is_admin"] = False

upload_col, admin_col = st.columns([1, 1])

with upload_col:
    st.subheader("Report Submission")
    st.write("Upload one PDF and two screenshots.")

    with st.form("report_upload_form", clear_on_submit=False):
        pdf = st.file_uploader("Structured Report (PDF)", type=["pdf"], key="pdf_upload")
        screenshot1 = st.file_uploader("Screenshot 1", type=["png", "jpg", "jpeg"], key="shot1_upload")
        screenshot2 = st.file_uploader("Screenshot 2", type=["png", "jpg", "jpeg"], key="shot2_upload")

        submitted = st.form_submit_button("Submit Report")

    if submitted:
        if not pdf or not screenshot1 or not screenshot2:
            st.error("Please upload 1 PDF and 2 screenshots.")
        else:
            try:
                result = submit_report(pdf, screenshot1, screenshot2)
                st.success("Report submitted successfully.")
                st.info(f"Report ID: {result.get('report_id', 'N/A')}")
                st.caption("Detailed analysis is visible only in the admin panel.")
            except Exception as exc:
                st.error(f"Submission failed: {exc}")

with admin_col:
    st.subheader("Admin Panel")

    if not st.session_state["is_admin"]:
        password = st.text_input("Admin password", type="password")
        if st.button("Login as Admin"):
            if verify_password(password, settings.admin_password_hash):
                st.session_state["is_admin"] = True
                st.success("Admin access granted.")
            else:
                st.error("Invalid admin password.")
    else:
        if st.button("Logout Admin"):
            st.session_state["is_admin"] = False
            st.rerun()

        try:
            summary = fetch_summary()

            c1, c2, c3 = st.columns(3)
            c1.metric("Total Reports", summary.get("total_reports", 0))
            c2.metric("Critical Reports", len(summary.get("critical_vulnerabilities", [])))
            c3.metric("Tracked Attack Types", len(summary.get("common_attack_types", {})))

            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                st.subheader("Severity Distribution")
                sev_df = pd.DataFrame(
                    list(summary.get("severity_distribution", {}).items()),
                    columns=["Severity", "Count"],
                )
                if not sev_df.empty:
                    st.bar_chart(sev_df.set_index("Severity"))
                else:
                    st.info("No reports available yet.")

            with chart_col2:
                st.subheader("Common Attack Types")
                type_df = pd.DataFrame(
                    list(summary.get("common_attack_types", {}).items()),
                    columns=["Attack Type", "Count"],
                )
                if not type_df.empty:
                    st.bar_chart(type_df.set_index("Attack Type"))
                else:
                    st.info("No attack types tracked yet.")

            st.markdown("---")
            st.subheader("Filter and Search Reports")
            f_col1, f_col2, f_col3 = st.columns(3)
            with f_col1:
                sel_severity = st.selectbox("Severity Rating", ["All", "Low", "Medium", "High", "Critical"])
            with f_col2:
                sel_limit = st.number_input("Page Limit", min_value=1, max_value=200, value=20)
            with f_col3:
                sel_skip = st.number_input("Skip Offset", min_value=0, value=0)

            reports = fetch_reports(skip=sel_skip, limit=sel_limit, severity=sel_severity)

            st.subheader("Recent Reports")
            if reports:
                flattened = []
                for report in reports:
                    fields = report.get("extracted_fields", {})
                    score = report.get("score_breakdown", {})
                    flattened.append(
                        {
                            "report_id": report.get("report_id"),
                            "created_at": report.get("created_at"),
                            "severity": report.get("severity"),
                            "vulnerability_type": fields.get("vulnerability_type"),
                            "affected_asset": fields.get("affected_asset"),
                            "total_score": score.get("total_score"),
                        }
                    )
                st.dataframe(pd.DataFrame(flattened), use_container_width=True)

                selected_id = st.text_input("Inspect report by ID")
                if selected_id:
                    details = requests.get(f"{API_BASE_URL}/reports/{selected_id}", timeout=10)
                    if details.status_code == 200:
                        st.json(details.json())
                        try:
                            rexport = requests.get(f"{API_BASE_URL}/reports/{selected_id}/export", timeout=10)
                            if rexport.ok:
                                st.download_button(
                                    label="📥 Export Report to Markdown",
                                    data=rexport.text,
                                    file_name=f"audit_report_{selected_id}.md",
                                    mime="text/markdown",
                                    key="admin_download_btn"
                                )
                        except Exception as e:
                            st.caption(f"Could not load export link: {e}")
                    else:
                        st.warning("Report not found.")
            else:
                st.info("No report data available.")

        except Exception as exc:
            st.error(f"Admin panel cannot reach API: {exc}")
