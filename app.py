import csv
import io

import streamlit as st

import database
from predictor import analyze_message
from url_scanner import analyze_url

st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Keep the interface readable: light background, dark text, blue actions.
st.markdown("""
<style>
.stApp { background: #F4F7FB; color: #172033; }
[data-testid="stSidebar"] { background: #E7EEF8; border-right: 1px solid #CBD5E1; }
[data-testid="stSidebar"] * { color: #172033 !important; }
h1, h2, h3, h4, p, label { color: #172033; }
[data-testid="stMetric"] {
    background: #FFFFFF; border: 1px solid #D7E0EC;
    border-radius: 14px; padding: 15px;
    box-shadow: 0 2px 8px rgba(15, 23, 42, .05);
}
[data-testid="stMetricLabel"] { color: #475569 !important; }
[data-testid="stMetricValue"] { color: #102A43 !important; }
.stButton button, .stDownloadButton button {
    background: #155EEF; color: white; border: 0;
    border-radius: 9px; font-weight: 650; min-height: 42px;
}
.stButton button:hover, .stDownloadButton button:hover {
    background: #1049C7; color: white;
}
input, textarea { background: white !important; color: #172033 !important; }
button[data-baseweb="tab"] { color: #334155 !important; font-weight: 650; }
button[data-baseweb="tab"][aria-selected="true"] { color: #155EEF !important; }
[data-testid="stExpander"] { background: white; border: 1px solid #D7E0EC; border-radius: 10px; }
.small-note { color: #475569; font-size: .9rem; }
footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

if "latest_url_result" not in st.session_state:
    st.session_state.latest_url_result = None
if "latest_message_result" not in st.session_state:
    st.session_state.latest_message_result = None

def risk_group(score):
    score = float(score)
    if score >= 70:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"

def message_warning_signs(message):
    text = message.lower()
    groups = {
        "Urgent language": ["urgent", "immediately", "blocked", "suspended"],
        "Banking or KYC wording": ["kyc", "bank account", "upi"],
        "Sensitive information": ["otp", "password", "pin", "cvv"],
        "Prize-related wording": ["lottery", "winner", "claim prize"],
    }
    found = [name for name, words in groups.items() if any(w in text for w in words)]
    if "http://" in text or "https://" in text:
        found.append("Contains a website link")
    return found

records = database.get_all_scans()
total = len(records)
high = sum(float(r[4]) >= 70 for r in records)
medium = sum(30 <= float(r[4]) < 70 for r in records)
low = sum(float(r[4]) < 30 for r in records)
url_total = sum(r[1] == "URL" for r in records)
message_total = sum(r[1] == "Message" for r in records)

with st.sidebar:
    st.title("🛡️ ScamShield AI")
    st.caption("DIGITAL PROTECTION PLATFORM")
    st.divider()
    st.subheader("Project overview")
    st.write("**Version:** 1.0 — GitHub release")
    st.write("Python • Machine Learning • SQLite")
    st.divider()
    st.subheader("Live statistics")
    st.metric("Total scans", total)
    st.metric("High caution", high)
    st.caption("Detect. Analyse. Protect.")

st.title("🛡️ ScamShield AI")
st.subheader("Detect. Analyse. Protect.")
st.write(
    "Check website links and suspicious messages. The app explains warning "
    "indicators to help you decide what to verify."
)
st.warning(
    "Important: This is an educational screening tool. It does not verify "
    "website ownership, live reputation or actual fraud. A low score never "
    "proves a link or message is safe."
)

st.subheader("Your scan summary")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total scans", total)
c2.metric("High caution", high)
c3.metric("Medium caution", medium)
c4.metric("Low caution", low)
st.divider()

overview, url_tab, message_tab, analytics, history, guide = st.tabs([
    "🏠 Overview", "🔗 URL Scanner", "💬 Message Scanner",
    "📊 Analytics", "📁 Scan History", "🛡️ Safety Guide"
])

with overview:
    st.header("Welcome")
    st.write("Choose a tool to get started.")
    a, b = st.columns(2)
    with a:
        with st.container(border=True):
            st.subheader("🔗 Website link checker")
            st.write("Checks URL structure, suspicious wording, shortened links and selected risk indicators.")
    with b:
        with st.container(border=True):
            st.subheader("💬 AI message checker")
            st.write("Uses a trained TF-IDF and Logistic Regression model to estimate SMS spam similarity.")
    a, b = st.columns(2)
    with a:
        with st.container(border=True):
            st.subheader("📊 Scan analytics")
            st.write("Review stored scan totals and risk groups.")
    with b:
        with st.container(border=True):
            st.subheader("📁 Scan history")
            st.write("Search past scans and export records as CSV.")
    st.subheader("How to use")
    st.markdown(
        "1. Open **URL Scanner** or **Message Scanner**.\n"
        "2. Paste the link or message and select the scan button.\n"
        "3. Read the warning score and the reasons.\n"
        "4. Verify suspicious requests using official sources before acting."
    )

with url_tab:
    st.header("🔗 Website Link Checker")
    st.write("Paste the actual link. The scanner works offline and does not open the link.")
    url_input = st.text_input(
        "Website URL", placeholder="https://example.com", key="url_input"
    )
    if st.button("Analyse URL", key="url_scan"):
        if not url_input.strip():
            st.warning("Please enter a website URL.")
        else:
            try:
                result = analyze_url(url_input)
                database.save_scan(
                    "URL", url_input, result["prediction"], result["risk_score"]
                )
                st.session_state.latest_url_result = {"url": url_input, **result}
                st.rerun()
            except Exception as exc:
                st.error(f"Could not analyse this URL: {exc}")

    result = st.session_state.latest_url_result
    if result:
        st.divider()
        st.subheader("Analysis result")
        st.write("**Domain:**", result.get("domain") or "Not identified")
        with st.expander("Show full URL"):
            st.code(result["url"], language=None)

        score_col, level_col = st.columns([1, 2])
        with score_col:
            st.metric("Rule-based caution score", f'{result["risk_score"]}/100')
            st.progress(min(max(result["risk_score"] / 100, 0), 1))
        with level_col:
            level = result.get("risk_level", risk_group(result["risk_score"]))
            if level == "High":
                st.error("HIGH CAUTION — multiple warning indicators")
            elif level == "Medium":
                st.warning("NEEDS REVIEW — warning indicators found")
            elif result.get("review_required"):
                st.warning("MANUAL REVIEW — a category or warning indicator was found; this is not proof of fraud.")
            else:
                st.info("NO MAJOR RULE WARNINGS — website remains unverified")

        st.write("**Summary:**", result["prediction"])
        st.subheader("Warning indicators")
        if result["reasons"]:
            for reason in result["reasons"]:
                st.write(f"• {reason}")
        else:
            st.write("No warning patterns from this rule set were detected.")
        if result.get("informational"):
            st.subheader("Additional context")
            for item in result["informational"]:
                st.caption("ℹ️ " + item)
        st.caption(
            "The score is a heuristic caution score, not a probability of fraud. "
            "Gambling-related words identify a content category, not proof of a scam. "
            "No live threat-intelligence lookup is performed."
        )

with message_tab:
    st.header("💬 SMS / WhatsApp Message Checker")
    st.write("Paste a message to estimate whether it resembles spam in the model's training data.")
    message_input = st.text_area(
        "Message text", placeholder="Paste a suspicious message here...", height=150
    )
    if st.button("Analyse Message", key="message_scan"):
        if not message_input.strip():
            st.warning("Please enter a message.")
        else:
            try:
                result = analyze_message(message_input)
                signs = message_warning_signs(message_input)
                database.save_scan(
                    "Message", message_input, result["prediction"], result["risk_score"]
                )
                st.session_state.latest_message_result = {
                    "message": message_input,
                    **result,
                    "reasons": signs,
                }
                st.rerun()
            except Exception as exc:
                st.error(f"Could not analyse this message: {exc}")

    result = st.session_state.latest_message_result
    if result:
        st.divider()
        st.subheader("AI analysis result")
        score = float(result["risk_score"])
        st.metric("Estimated SMS spam score", f"{score:.2f}%")
        st.progress(min(max(score / 100, 0), 1))
        if score >= 70:
            st.error("HIGH RISK — the model found strong spam-like patterns.")
        elif score >= 40:
            st.warning("MEDIUM RISK — review the message carefully.")
        else:
            st.success("LOW MODEL SCORE — this does not guarantee the message is safe.")
        st.write("**Model prediction:**", result["prediction"])
        st.subheader("Additional warning signs")
        if result["reasons"]:
            for reason in result["reasons"]:
                st.write("• " + reason)
        else:
            st.write("No listed keyword warning signs were detected.")
        st.caption(
            "The model was trained on the UCI SMS Spam Collection. "
            "It estimates spam similarity, not confirmed financial fraud."
        )

with analytics:
    st.header("📊 Analytics")
    if total == 0:
        st.info("No scans yet. Start with the URL or Message Scanner.")
    else:
        st.subheader("Risk groups")
        for label, count in [("High", high), ("Medium", medium), ("Low", low)]:
            st.write(f"**{label}:** {count} scans")
            st.progress(count / total)
        st.divider()
        st.subheader("Scan types")
        st.write(f"**URL scans:** {url_total}")
        st.progress(url_total / total)
        st.write(f"**Message scans:** {message_total}")
        st.progress(message_total / total)
        st.caption("Risk groups describe this app's screening scores, not confirmed fraud incidents.")

with history:
    st.header("📁 Scan History")
    if not records:
        st.info("No saved scans yet.")
    else:
        search = st.text_input("Search content or prediction")
        type_filter = st.selectbox("Scan type", ["All", "URL", "Message"])
        risk_filter = st.selectbox("Risk group", ["All", "High", "Medium", "Low"])
        filtered = []
        for row in records:
            scan_id, scan_type, content, prediction, score, scan_time = row
            if type_filter != "All" and scan_type != type_filter:
                continue
            if risk_filter != "All" and risk_group(score) != risk_filter:
                continue
            if search.lower() not in f"{content} {prediction} {scan_type}".lower():
                continue
            filtered.append(row)

        st.write(f"Showing {len(filtered)} of {total} records.")
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Type", "Content", "Prediction", "Score", "Time"])
        writer.writerows(filtered)
        st.download_button(
            "⬇️ Download CSV",
            data=output.getvalue(),
            file_name="scamshield_scan_history.csv",
            mime="text/csv",
        )
        for row in filtered:
            scan_id, scan_type, content, prediction, score, scan_time = row
            with st.expander(f"#{scan_id} | {scan_type} | {risk_group(score)} caution"):
                st.write("**Prediction:**", prediction)
                st.write("**Score:**", f"{float(score):.2f}")
                st.write("**Time:**", scan_time)
                st.code(content, language=None)

        st.divider()
        st.warning("This permanently deletes all saved scan records.")
        confirm = st.checkbox("I understand and want to clear all history.")
        if st.button("Clear all scan history", disabled=not confirm):
            database.clear_history()
            st.session_state.latest_url_result = None
            st.session_state.latest_message_result = None
            st.rerun()

with guide:
    st.header("🛡️ Digital Safety Guide")
    st.subheader("Protect your money and personal information")
    st.markdown(
        "- Never share OTP, UPI PIN, ATM PIN, CVV or passwords.\n"
        "- Verify bank and KYC requests through the official bank app or website.\n"
        "- Do not pay money to receive a prize, job or loan.\n"
        "- Do not install APK files sent by unknown people.\n"
        "- Do not allow strangers to control your screen or device.\n"
        "- If you suspect financial cyber fraud in India, contact your bank promptly "
        "and report it through the official cybercrime helpline **1930**."
    )
    with st.expander("How the URL scanner works"):
        st.write("It checks URL structure and selected wording. It does not visit websites or query a live blocklist.")
    with st.expander("How the message model works"):
        st.write("TF-IDF converts message text into numeric features; Logistic Regression estimates spam similarity.")
    with st.expander("What does the score mean?"):
        st.write("The URL score is a rule-based caution indicator. The message score estimates similarity to spam in the training dataset. Neither is a verified fraud probability.")
    st.error(
        "ScamShield AI is an educational prototype. It cannot guarantee that a website "
        "or message is safe and must not replace official bank or security advice."
    )

st.divider()
st.caption("🛡️ ScamShield AI | Detect. Analyse. Protect. | Python • Machine Learning • SQLite")
