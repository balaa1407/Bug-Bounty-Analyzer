import os

import pandas as pd
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000")
ADMIN_PANEL_PASSWORD = os.getenv("ADMIN_PANEL_PASSWORD", "admin123")

st.set_page_config(page_title="Bug Bounty Analyzer", layout="wide")
st.title("Bug Bounty Vulnerability Report Analyzer")
st.caption("Single-page workflow: reporter upload + admin-only results panel")


@st.cache_data(ttl=20)
def fetch_summary():
    response = requests.get(f"{API_BASE_URL}/analytics/summary", timeout=10)
    response.raise_for_status()
    return response.json()


@st.cache_data(ttl=20)
def fetch_reports():
    response = requests.get(f"{API_BASE_URL}/reports?limit=200", timeout=10)
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
            if password == ADMIN_PANEL_PASSWORD:
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
            reports = fetch_reports()

            c1, c2, c3 = st.columns(3)
            c1.metric("Total Reports", summary.get("total_reports", 0))
            c2.metric("Critical Reports", len(summary.get("critical_vulnerabilities", [])))
            c3.metric("Tracked Attack Types", len(summary.get("common_attack_types", {})))

            st.subheader("Severity Distribution")
            sev_df = pd.DataFrame(
                list(summary.get("severity_distribution", {}).items()),
                columns=["Severity", "Count"],
            )
            if not sev_df.empty:
                st.bar_chart(sev_df.set_index("Severity"))
            else:
                st.info("No reports available yet.")

            st.subheader("Common Attack Types")
            type_df = pd.DataFrame(
                list(summary.get("common_attack_types", {}).items()),
                columns=["Attack Type", "Count"],
            )
            if not type_df.empty:
                st.dataframe(type_df, use_container_width=True)

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
                    else:
                        st.warning("Report not found.")
            else:
                st.info("No report data available.")

        except Exception as exc:
            st.error(f"Admin panel cannot reach API: {exc}")
