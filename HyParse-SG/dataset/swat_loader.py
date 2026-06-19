import pandas as pd
from dataset.base import DatasetLog

class SWaTLoader:
    """
    Loader for SWaT telemetry dataset.
    Converts telemetry rows into synthetic
    event-like log messages.
    """

    def __init__(self, file_path, limit=None):
        self.file_path = file_path
        self.limit = limit

    def _safe(self, value):
        try:
            if pd.isna(value):
                return 0

            if value == float("inf"):
                return 0

            if value == float("-inf"):
                return 0

            return value

        except Exception:
            return 0

    def _get_swat_status(self, row):
        candidates = [
            "Normal/Attack",
            "Normal Attack",
            "Label",
            "label",
            "Event",
            "event",
            "ATTACK"
        ]

        for col in candidates:
            if col in row.index:
                value = str(row[col]).strip().upper()

                if value in {"ATTACK", "1", "TRUE"}:
                    return "ATTACK"

                if value in {"NORMAL", "0", "FALSE", "BENIGN"}:
                    return "NORMAL"

        return "UNKNOWN"

    def _build_log(self, row):
        fields = []

        status = self._get_swat_status(row)

        fields.append("DATASET=SWAT")
        fields.append("EVENT=PROCESS_STATE")
        fields.append(f"STATUS={status}")

        important = [
            "FIT101",
            "LIT101",
            "MV101",
            "P101",
            "P102",
            "AIT201",
            "AIT202",
            "AIT203",
            "FIT201",
            "DPIT301",
            "AIT503"
        ]

        for field in important:
            if field in row:
                value = self._safe(row[field])
                fields.append(f"{field}={value}")

        return " ".join(fields)

    def load(self):
        df = pd.read_csv(self.file_path)

        if self.limit:
            df = df.head(self.limit)

        logs = []

        for idx, row in df.iterrows():
            raw = self._build_log(row)

            status = self._get_swat_status(row)

            is_anomaly = (
                status == "ATTACK"
            )

            logs.append(
                DatasetLog(
                    log_id=idx,
                    raw_text=raw,
                    is_anomaly=is_anomaly,
                    template_label="PROCESS_STATE",
                    group_label="PROCESS_STATE"
                )
            )

        return logs