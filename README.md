# SOC Log Analyzer & Threat Detection System

A hands-on cybersecurity portfolio project by **PhoebeAstrid**. It uses Python and Streamlit to review synthetic authentication logs, flag suspicious login patterns, and explain alert risk levels in a dashboard. The rules are educational examples—not proof of an attack or a substitute for a production security system.

This project demonstrates practical learning in CSV data cleanup, time-based detection rules, basic risk scoring, testing, and dashboard design.

## Features

- Reads and validates CSV authentication logs.
- Normalizes timestamps to UTC, cleans usernames/status values, and counts invalid rows.
- Detects a burst of failed logins from one source IP within a configurable rolling time window. One alert is shown per qualifying burst, with its peak failure count.
- Flags a successful login for the same username and IP within ten minutes after a qualifying failure burst when that username also has at least the threshold number of recent failures.
- Assigns LOW, MEDIUM, or HIGH risk labels using documented heuristics.
- Shows summary metrics, activity charts, risk information, and an alert table in a styled dashboard.
- Allows alerts to be downloaded as a CSV report.
- Includes unit tests for parsing, detection boundaries, and risk labels.

## Project structure

```text
soc-log-analyzer/
├── data/sample_logs.csv
├── reports/                 # Generated reports (ignored by Git)
├── src/
│   ├── __init__.py
│   ├── log_parser.py
│   ├── detection_rules.py
│   └── risk_scoring.py
├── tests/test_detection.py
├── app.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10 or newer (Python 3.10–3.13 is recommended for broad package compatibility).
- Internet access for the initial installation of the packages in `requirements.txt`.

## Setup and run on Windows (PowerShell)

Open PowerShell in this project folder, then create a virtual environment and install dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run the tests:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

Start the dashboard:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Streamlit prints a local URL (usually `http://localhost:8501`) to open in your browser. The app loads `data/sample_logs.csv` from the project, even if Streamlit is started with a different working directory.

On macOS/Linux, use `python3 -m venv .venv`, then `.venv/bin/python -m pip install -r requirements.txt`, `.venv/bin/python -m pytest`, and `.venv/bin/python -m streamlit run app.py`.

## Using the dashboard

- Use the sidebar to choose the failed-attempt threshold and rolling window.
- Review the event metrics, activity chart, and detected-alert evidence.
- Select **Download alerts as CSV** to save a report when there are alerts.
- Expand **View cleaned source logs** to inspect the normalized rows and see how many invalid rows were skipped.

To analyze another dataset, replace `data/sample_logs.csv` with a CSV containing these column names: `timestamp`, `username`, `source_ip`, and `status`. Status values must be `SUCCESS` or `FAILED` (case-insensitive); malformed rows are skipped. Use synthetic data only for this portfolio project.

## Detection rules

1. **Repeated failed logins:** by default, at least five failed attempts from the same source IP inside a rolling five-minute window. The alert reports one burst and its peak count rather than repeating for every event.
2. **Success after repeated failures:** a successful login for the same username and source IP within ten minutes after a qualifying burst, provided the same username/IP has at least the selected threshold of failures in the preceding fifteen minutes.

Both threshold and window can be changed in the dashboard sidebar. The configured time-window boundary is inclusive.

## Risk labels

- **HIGH:** success after repeated failures, or eight or more failures in a detected burst.
- **MEDIUM:** five to seven failures in a detected burst.
- **LOW:** fewer than five failures in a detected burst (possible when the dashboard threshold is set below five).

These simple labels are educational heuristics and are not proof of malicious activity.

## Data and privacy

The included sample log data is synthetic. IP addresses use documentation-reserved ranges. Do not commit real authentication logs, personal information, credentials, or secrets to a public repository.

## Limitations

- This is a learning demo, not a production SIEM.
- It analyzes a local CSV and does not monitor systems in real time.
- Detection rules can produce false positives and miss suspicious activity.
- It does not block IP addresses or take actions on live systems.
- The rules are simple heuristics and do not account for every authentication pattern or threat context.

## Future improvements

- Add more log sources and detection rules.
- Add JSON log support and configurable rule settings.
- Improve alert grouping and explainability.
- Add more tests for malformed files and time-window boundaries.

## License

MIT. See `LICENSE`.
