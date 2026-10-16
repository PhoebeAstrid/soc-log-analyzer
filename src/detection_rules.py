"""Simple defensive rules for synthetic login logs."""
import pandas as pd

ALERT_COLUMNS = [
    "timestamp", "username", "source_ip", "rule", "failed_attempts", "reason"
]


def detect_suspicious_logins(logs, threshold=5, window_minutes=5):
    """
    Flag a source IP with threshold failed attempts in a rolling time window.
    Also flag a success for the same IP and username within 10 minutes after
    a qualifying burst of failures. Alerts are indicators, not proof of attack.
    """
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    if isinstance(window_minutes, bool) or not isinstance(window_minutes, int) or window_minutes < 1:
        raise ValueError("window_minutes must be a positive integer")

    missing = {"timestamp", "username", "source_ip", "status"} - set(logs.columns)
    if missing:
        raise ValueError(f"logs are missing required columns: {', '.join(sorted(missing))}")
    if logs.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    df = logs.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["username"] = df["username"].astype("string").str.strip()
    df["source_ip"] = df["source_ip"].astype("string").str.strip()
    df["status"] = df["status"].astype("string").str.strip().str.upper()
    df = df.dropna(subset=["timestamp", "username", "source_ip"])
    df = df[df["status"].isin(["SUCCESS", "FAILED"])]
    if df.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    df = df.sort_values("timestamp")

    alerts = []
    window = pd.Timedelta(minutes=window_minutes)
    qualifying_bursts = []

    for ip, group in df.groupby("source_ip"):
        failures = group[group["status"] == "FAILED"].sort_values("timestamp")
        times = failures["timestamp"].tolist()
        usernames = failures["username"].tolist()
        left = 0
        burst_active = False
        alert_index = None

        for right, current_time in enumerate(times):
            if right > 0 and current_time - times[right - 1] > window:
                burst_active = False
                alert_index = None
            while current_time - times[left] > window:
                left += 1

            attempts = right - left + 1
            if attempts < threshold:
                burst_active = False
                alert_index = None
                continue

            if not burst_active:
                burst_active = True
                alert_index = len(alerts)
                qualifying_bursts.append((ip, current_time))
                alerts.append({
                    "timestamp": current_time,
                    "username": usernames[right],
                    "source_ip": ip,
                    "rule": "Repeated failed logins",
                    "failed_attempts": attempts,
                    "reason": f"At least {threshold} failed attempts from this IP within {window_minutes} minutes.",
                })
            elif attempts > alerts[alert_index]["failed_attempts"]:
                # Keep one alert per burst and preserve the peak count for scoring.
                alerts[alert_index]["timestamp"] = current_time
                alerts[alert_index]["username"] = usernames[right]
                alerts[alert_index]["failed_attempts"] = attempts
                alerts[alert_index]["reason"] = (
                    f"{attempts} failed attempts from this IP within {window_minutes} minutes."
                )

    for _, success in df[df["status"] == "SUCCESS"].iterrows():
        for ip, burst_time in qualifying_bursts:
            if success["source_ip"] == ip and burst_time <= success["timestamp"] <= burst_time + pd.Timedelta(minutes=10):
                recent_failures = df[
                    (df["source_ip"] == ip)
                    & (df["username"] == success["username"])
                    & (df["status"] == "FAILED")
                    & (df["timestamp"] <= success["timestamp"])
                    & (df["timestamp"] >= success["timestamp"] - pd.Timedelta(minutes=15))
                ]
                if len(recent_failures) >= threshold:
                    alerts.append({
                        "timestamp": success["timestamp"],
                        "username": success["username"],
                        "source_ip": ip,
                        "rule": "Success after repeated failures",
                        "failed_attempts": len(recent_failures),
                        "reason": "A successful login followed repeated failures for the same username and IP."
                    })
                    break

    result = pd.DataFrame(alerts, columns=ALERT_COLUMNS)
    if not result.empty:
        result = result.drop_duplicates(subset=["timestamp", "username", "source_ip", "rule"])
        result = result.sort_values("timestamp").reset_index(drop=True)
    return result
