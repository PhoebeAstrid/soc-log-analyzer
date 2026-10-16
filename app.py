from pathlib import Path
import streamlit as st

from src.log_parser import load_logs
from src.detection_rules import detect_suspicious_logins
from src.risk_scoring import assign_risk

st.set_page_config(page_title="SOC Log Analyzer", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
        .stApp { background: radial-gradient(ellipse at 15% 0%, #172b49 0, #0b1220 44%, #080d17 100%); color: #e7edf7; }
        [data-testid="stHeader"] { background: rgba(8, 13, 23, 0.72); }
        [data-testid="stSidebar"] { background: #0c1524; border-right: 1px solid #203149; }
        [data-testid="stMetric"] { background: linear-gradient(145deg, #14243a, #101a2b); border: 1px solid #263c58; padding: 18px 20px; border-radius: 14px; }
        [data-testid="stMetricLabel"] { color: #9db0c9; }
        [data-testid="stMetricValue"] { color: #f4f7fb; }
        h1, h2, h3 { color: #f4f7fb; }
        div[data-testid="stDataFrame"] { border: 1px solid #263c58; border-radius: 12px; overflow: hidden; }
        .hero { padding: 26px 30px; margin: 8px 0 24px; border: 1px solid #294866; border-radius: 18px; background: linear-gradient(115deg, rgba(20, 44, 70, .94), rgba(15, 28, 46, .78)); }
        .eyebrow { color: #65d5c2; font-size: .78rem; letter-spacing: .16em; text-transform: uppercase; font-weight: 700; }
        .hero h1 { margin: 8px 0; font-size: 2.15rem; }
        .hero p { color: #b8c7da; margin: 0; }
        .safe-note { color: #95a8c0; font-size: .84rem; padding-top: 5px; }
</style>
<div class="hero">
    <div class="eyebrow">Security operations · Synthetic data lab</div>
    <h1>SOC Log Analyzer</h1>
    <p>Review authentication activity, investigate heuristic alerts, and export a concise incident report.</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("Detection settings")
    threshold = st.slider("Failed attempts threshold", min_value=3, max_value=10, value=5)
    window_minutes = st.slider("Time window (minutes)", min_value=1, max_value=15, value=5)
    st.caption("Rules are heuristic indicators, not proof of malicious activity.")

try:
    logs = load_logs(Path(__file__).resolve().parent / "data" / "sample_logs.csv")
except Exception as exc:
    st.error(f"Could not load sample logs: {exc}")
    st.stop()

alerts = detect_suspicious_logins(logs, threshold=threshold, window_minutes=window_minutes)
alerts = assign_risk(alerts)

total = len(logs)
successes = int((logs["status"] == "SUCCESS").sum())
failures = int((logs["status"] == "FAILED").sum())
high_risk = int((alerts["risk_level"] == "HIGH").sum()) if not alerts.empty else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analyzed", f"{total:,}")
c2.metric("Failed logins", f"{failures:,}", delta=f"{successes:,} successful", delta_color="off")
c3.metric("High-risk alerts", f"{high_risk:,}")
c4.metric("Total alerts", f"{len(alerts):,}")

st.subheader("Authentication activity")
activity = logs.assign(minute=logs["timestamp"].dt.floor("min")).groupby(
    ["minute", "status"]
).size().unstack(fill_value=0).reindex(columns=["FAILED", "SUCCESS"], fill_value=0)
if not activity.empty:
    st.line_chart(activity.rename_axis("minute").reset_index(), x="minute", y=["FAILED", "SUCCESS"])
else:
    st.info("No login activity to display.")

st.subheader("Detection results")
if alerts.empty:
    st.success("No alerts were detected using the current settings.")
else:
    risk_counts = alerts["risk_level"].value_counts()
    chart_col, summary_col = st.columns([1, 2])
    with chart_col:
        st.caption("Alerts grouped by severity")
        st.bar_chart(risk_counts, color="#45c4b0")
    with summary_col:
        st.caption("Review the rule, source, and evidence behind each alert")
        st.dataframe(alerts, width="stretch", hide_index=True)

    st.subheader("Export report")
    csv_data = alerts.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download alerts as CSV",
        data=csv_data,
        file_name="soc_alert_report.csv",
        mime="text/csv",
    )

with st.expander("View cleaned source logs"):
    st.dataframe(logs, width="stretch", hide_index=True)
    invalid_rows = logs.attrs.get("invalid_rows", 0)
    st.caption(f"Invalid rows skipped: {invalid_rows}")

st.divider()
st.markdown('<div class="safe-note">Cybersecurity portfolio demo · Synthetic logs only · No connection to or action on live systems</div>', unsafe_allow_html=True)
