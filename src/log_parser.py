"""Load and validate synthetic authentication logs."""
from pathlib import Path
import pandas as pd

REQUIRED_COLUMNS = {"timestamp", "username", "source_ip", "status"}

def load_logs(path="data/sample_logs.csv"):
    """Return valid log rows as a DataFrame; raise a helpful error for bad files."""
    file_path = Path(path)
    if not file_path.is_absolute() and not file_path.exists():
        file_path = Path(__file__).resolve().parent.parent / file_path
    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    try:
        df = pd.read_csv(file_path)
    except pd.errors.EmptyDataError as exc:
        raise ValueError(f"CSV file is empty: {file_path}") from exc
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"CSV is missing required columns: {', '.join(sorted(missing))}")

    df = df.copy()
    # Treat timestamps without an explicit timezone as UTC and normalize offsets.
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["username"] = df["username"].astype("string").str.strip()
    df["source_ip"] = df["source_ip"].astype("string").str.strip()
    df["status"] = df["status"].astype("string").str.strip().str.upper()

    valid = (
        df["timestamp"].notna()
        & df["username"].notna() & df["username"].ne("")
        & df["source_ip"].notna() & df["source_ip"].ne("")
        & df["status"].isin(["SUCCESS", "FAILED"])
    )
    invalid_count = int((~valid).sum())
    clean = df.loc[valid].sort_values("timestamp").reset_index(drop=True)
    clean.attrs["invalid_rows"] = invalid_count
    return clean
