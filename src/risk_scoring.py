"""Transparent risk labels for detected alerts."""
import pandas as pd

def assign_risk(alerts):
    """Add transparent severity labels based on rule type and failure count."""
    result = alerts.copy()
    if result.empty:
        result["risk_level"] = pd.Series(dtype="string")
        return result

    def risk_for(row):
        attempts = int(row["failed_attempts"])
        if row["rule"] == "Success after repeated failures" or attempts >= 8:
            return "HIGH"
        if attempts >= 5:
            return "MEDIUM"
        return "LOW"

    result["risk_level"] = result.apply(risk_for, axis=1)
    return result
