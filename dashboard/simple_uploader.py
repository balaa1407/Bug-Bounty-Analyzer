import os
import io
import requests
import streamlit as st


API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")


def main():
    st.set_page_config(page_title="Bug Bounty Quick Score", page_icon="🧪", layout="centered")
    st.title("Bug Bounty Analyzer — Quick Score")
    st.caption("Upload a PDF report and up to two screenshots to get the score.")

    with st.expander("API Status", expanded=False):
        try:
            r = requests.get(f"{API_BASE_URL}/health", timeout=5)
            if r.ok:
                data = r.json()
                st.success(f"API OK — storage: {data.get('storage_mode', 'unknown')}")
            else:
                st.warning(f"API responded with status {r.status_code}")
        except Exception as e:
            st.warning(f"Could not reach API at {API_BASE_URL}. Error: {e}")

    st.subheader("Upload Report")
    pdf_file = st.file_uploader("PDF Report", type=["pdf"], accept_multiple_files=False)
    screenshots = st.file_uploader(
        "Screenshots (up to 2)", type=["png", "jpg", "jpeg"], accept_multiple_files=True
    )

    if screenshots and len(screenshots) > 2:
        st.info("Only the first two screenshots will be used.")

    submit = st.button("Analyze")

    if submit:
        if not pdf_file:
            st.error("Please upload a PDF report.")
            return

        # Prepare multipart/form-data files payload
        files = []
        pdf_bytes = pdf_file.read()
        files.append((
            "pdf",
            (pdf_file.name or "report.pdf", pdf_bytes, "application/pdf")
        ))

        if screenshots:
            # Take up to 2 screenshots
            shots = screenshots[:2]
            for idx, shot in enumerate(shots, start=1):
                shot_bytes = shot.read()
                mime = _guess_mime(shot.name)
                files.append((
                    f"screenshot{idx}",
                    (shot.name or f"screenshot{idx}.png", shot_bytes, mime)
                ))

        with st.spinner("Analyzing…"):
            try:
                resp = requests.post(f"{API_BASE_URL}/analyze", files=files, timeout=60)
            except Exception as e:
                st.error(f"Request failed: {e}")
                return

        if not resp.ok:
            try:
                err = resp.json()
            except Exception:
                err = {"detail": resp.text}
            st.error(f"API error ({resp.status_code}): {err}")
            return

        data = resp.json()
        _render_result(data)


def _render_result(data: dict):
    st.success("Analysis complete")
    severity = data.get("severity")
    score_breakdown = data.get("score_breakdown", {})
    total_score = score_breakdown.get("total_score") or data.get("total_score")

    cols = st.columns(2)
    with cols[0]:
        st.metric(label="Severity", value=str(severity))
    with cols[1]:
        st.metric(label="Total Score", value=str(total_score))

    with st.expander("Score Breakdown", expanded=True):
        st.write({k: v for k, v in score_breakdown.items() if k != "total_score"})

    extracted = data.get("extracted_fields", {})
    with st.expander("Extracted Fields", expanded=False):
        st.write(extracted)

    ocr = data.get("ocr_signals", {})
    if ocr:
        with st.expander("OCR Signals", expanded=False):
            st.write(ocr)

    explanation = data.get("explanation")
    if explanation:
        st.info(explanation)

    rem = data.get("remediation", [])
    if rem:
        st.subheader("Remediation Suggestions")
        for item in rem:
            st.write(f"• {item}")


def _guess_mime(name: str) -> str:
    name_lower = (name or "").lower()
    if name_lower.endswith(".jpg") or name_lower.endswith(".jpeg"):
        return "image/jpeg"
    return "image/png"


if __name__ == "__main__":
    main()
