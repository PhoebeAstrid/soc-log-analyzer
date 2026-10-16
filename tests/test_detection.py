import pandas as pd
import pytest
from src.detection_rules import detect_suspicious_logins
from src.risk_scoring import assign_risk

def sample_logs():
    rows = [
        ("2026-10-16T09:00:00", "bob", "192.0.2.11", "FAILED"),
        ("2026-10-16T09:01:00", "bob", "192.0.2.11", "FAILED"),
        ("2026-10-16T09:02:00", "bob", "192.0.2.11", "FAILED"),
        ("2026-10-16T09:03:00", "bob", "192.0.2.11", "FAILED"),
        ("2026-10-16T09:04:00", "bob", "192.0.2.11", "FAILED"),
        ("2026-10-16T09:05:00", "bob", "192.0.2.11", "SUCCESS"),
        ("2026-10-16T09:20:00", "alice", "192.0.2.10", "SUCCESS"),
    ]
    df = pd.DataFrame(rows, columns=["timestamp", "username", "source_ip", "status"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def test_repeated_failures_are_detected():
    alerts = detect_suspicious_logins(sample_logs(), threshold=5, window_minutes=5)
    assert not alerts.empty
    assert "Repeated failed logins" in set(alerts["rule"])

def test_success_after_failures_is_detected():
    alerts = detect_suspicious_logins(sample_logs(), threshold=5, window_minutes=5)
    assert "Success after repeated failures" in set(alerts["rule"])

def test_empty_logs_returns_no_alerts():
    empty = pd.DataFrame(columns=["timestamp", "username", "source_ip", "status"])
    alerts = detect_suspicious_logins(empty)
    assert alerts.empty

def test_risk_labels_are_added():
    alerts = assign_risk(detect_suspicious_logins(sample_logs()))
    assert "risk_level" in alerts.columns
    assert set(alerts["risk_level"]).issubset({"LOW", "MEDIUM", "HIGH"})


def test_one_alert_per_burst_keeps_peak_failure_count():
    logs = sample_logs().iloc[:5].copy()
    logs = pd.concat([logs, pd.DataFrame([
        ("2026-10-16T09:04:30", "bob", "192.0.2.11", "FAILED"),
        ("2026-10-16T09:05:00", "bob", "192.0.2.11", "FAILED"),
    ], columns=logs.columns)], ignore_index=True)
    logs["timestamp"] = pd.to_datetime(logs["timestamp"])

    alerts = detect_suspicious_logins(logs, threshold=5, window_minutes=5)
    burst_alerts = alerts[alerts["rule"] == "Repeated failed logins"]

    assert len(burst_alerts) == 1
    assert burst_alerts.iloc[0]["failed_attempts"] == 7


def test_threshold_and_window_boundary_are_inclusive():
    logs = pd.DataFrame([
        (f"2026-10-16T09:0{minute}:00", "bob", "192.0.2.11", "FAILED")
        for minute in range(5)
    ], columns=["timestamp", "username", "source_ip", "status"])
    logs["timestamp"] = pd.to_datetime(logs["timestamp"])

    alerts = detect_suspicious_logins(logs, threshold=5, window_minutes=4)

    assert len(alerts) == 1
    assert alerts.iloc[0]["failed_attempts"] == 5


def test_threshold_must_be_positive_integer():
    with pytest.raises(ValueError, match="threshold must be a positive integer"):
        detect_suspicious_logins(sample_logs(), threshold=0)


def test_risk_labels_follow_documented_levels():
    alerts = pd.DataFrame([
        ("Repeated failed logins", 4),
        ("Repeated failed logins", 5),
        ("Repeated failed logins", 8),
        ("Success after repeated failures", 3),
    ], columns=["rule", "failed_attempts"])

    result = assign_risk(alerts)

    assert result["risk_level"].tolist() == ["LOW", "MEDIUM", "HIGH", "HIGH"]
