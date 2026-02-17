import os

import pandas as pd
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000")

st.set_page_config(page_title="Bug Bounty Analyzer Dashboard", layout="wide")
st.title("Bug Bounty Vulnerability Analytics")


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
        for r in reports:
            fields = r.get("extracted_fields", {})
            score = r.get("score_breakdown", {})
            flattened.append(
                {
                    "report_id": r.get("report_id"),
                    "created_at": r.get("created_at"),
                    "severity": r.get("severity"),
                    "vulnerability_type": fields.get("vulnerability_type"),
                    "affected_asset": fields.get("affected_asset"),
                    "total_score": score.get("total_score"),
                }
            )
        st.dataframe(pd.DataFrame(flattened), use_container_width=True)
    else:
        st.info("No report data available.")

except Exception as exc:
    st.error(f"Dashboard cannot reach API: {exc}")
