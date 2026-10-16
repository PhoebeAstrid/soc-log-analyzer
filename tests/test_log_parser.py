import pandas as pd
import pytest

from src.log_parser import load_logs


def test_load_logs_normalizes_and_skips_invalid_rows(tmp_path):
    source = tmp_path / "synthetic.csv"
    source.write_text(
        "timestamp,username,source_ip,status\n"
        "2026-10-16T09:00:00,bob,192.0.2.11,failed\n"
        "not-a-date,alice,192.0.2.10,SUCCESS\n",
        encoding="utf-8",
    )

    logs = load_logs(source)

    assert len(logs) == 1
    assert logs.iloc[0]["status"] == "FAILED"
    assert logs.iloc[0]["timestamp"] == pd.Timestamp("2026-10-16T09:00:00Z")
    assert logs.attrs["invalid_rows"] == 1


def test_load_logs_reports_missing_columns(tmp_path):
    source = tmp_path / "incomplete.csv"
    source.write_text("timestamp,username\n2026-10-16,bob\n", encoding="utf-8")

    with pytest.raises(ValueError, match="CSV is missing required columns"):
        load_logs(source)


def test_load_logs_reports_empty_file(tmp_path):
    source = tmp_path / "empty.csv"
    source.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="CSV file is empty"):
        load_logs(source)