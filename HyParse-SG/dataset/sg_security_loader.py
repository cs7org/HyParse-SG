import pandas as pd
from dataset.base import DatasetLog

class SGSecurityLoader:
    """
    Smart Grid Security Dataset Loader.
    Converts tabular SG-security records into synthetic
    key-value log messages.
    """
    def __init__(self, file_path, limit=None):
        self.file_path = file_path
        self.limit = limit

    def _safe(self, value):
        try:
            if pd.isna(value):
                return "UNKNOWN"

            if value == float("inf"):
                return "UNKNOWN"

            if value == float("-inf"):
                return "UNKNOWN"

            value = str(value).strip()

            if value == "":
                return "UNKNOWN"

            return value.replace(" ", "_")

        except Exception:
            return "UNKNOWN"

    def _add_if_exists(self, fields, row, output_key, column_name):
        if column_name in row.index:
            fields.append(
                f"{output_key}={self._safe(row[column_name])}"
            )

    def _build_log(self, row):
        node_id = self._safe(row.get("node_id", "UNKNOWN"))
        access_behavior = self._safe(row.get("access_behavior", "UNKNOWN"))
        attack_type = self._safe(row.get("attack_type", "UNKNOWN"))
        policy_action = self._safe(row.get("policy_action", "UNKNOWN"))
        mtd_strategy = self._safe(row.get("mtd_strategy_used", "UNKNOWN"))
        attack_detected = self._safe(row.get("attack_detected", 0))

        return (
            f"NODE={node_id} "
            f"ACCESS={access_behavior} "
            f"ATTACK_TYPE={attack_type} "
            f"POLICY={policy_action} "
            f"MTD={mtd_strategy} "
            f"ATTACK_DETECTED={attack_detected} "
            f"VOLTAGE={self._safe(row.get('voltage_level', 'UNKNOWN'))} "
            f"FREQUENCY={self._safe(row.get('frequency_signal', 'UNKNOWN'))} "
            f"POWER_FLOW={self._safe(row.get('power_flow', 'UNKNOWN'))} "
            f"REACTIVE_POWER={self._safe(row.get('reactive_power', 'UNKNOWN'))} "
            f"COMM_SIZE={self._safe(row.get('communication_log_size', 'UNKNOWN'))} "
            f"THREAT_PROB={self._safe(row.get('threat_probability', 'UNKNOWN'))} "
            f"RISK_SCORE={self._safe(row.get('risk_score', 'UNKNOWN'))} "
            f"UNCERTAINTY={self._safe(row.get('uncertainty', 'UNKNOWN'))} "
            f"TEMPORAL_ENTROPY={self._safe(row.get('temporal_entropy', 'UNKNOWN'))} "
            f"SPECTRAL_ENERGY={self._safe(row.get('spectral_energy', 'UNKNOWN'))} "
            f"SPATIAL_CORR={self._safe(row.get('spatial_correlation', 'UNKNOWN'))}"
        )

    def _build_template(self, row):
        return (
            "NODE=<ID> "
            f"ACCESS={self._safe(row.get('access_behavior', 'UNKNOWN'))} "
            f"ATTACK_TYPE={self._safe(row.get('attack_type', 'UNKNOWN'))} "
            f"POLICY={self._safe(row.get('policy_action', 'UNKNOWN'))} "
            f"MTD={self._safe(row.get('mtd_strategy_used', 'UNKNOWN'))} "
            "ATTACK_DETECTED=<NUMBER> "
            "VOLTAGE=<NUMBER> "
            "FREQUENCY=<NUMBER> "
            "POWER_FLOW=<NUMBER> "
            "REACTIVE_POWER=<NUMBER> "
            "COMM_SIZE=<NUMBER> "
            "THREAT_PROB=<NUMBER> "
            "RISK_SCORE=<NUMBER> "
            "UNCERTAINTY=<NUMBER> "
            "TEMPORAL_ENTROPY=<NUMBER> "
            "SPECTRAL_ENERGY=<NUMBER> "
            "SPATIAL_CORR=<NUMBER>"
        )

    def _to_bool(self, value):
        value = str(value).strip().lower()

        return value in [
            "1",
            "1.0",
            "true",
            "yes",
            "attack",
            "detected"
        ]

    def load(self):
        df = pd.read_csv(self.file_path)

        if self.limit:
            df = df.head(self.limit)

        logs = []

        for idx, row in df.iterrows():
            raw = self._build_log(row)

            attack_detected = row.get(
                "attack_detected",
                0
            )

            is_anomaly = self._to_bool(
                attack_detected
            )

            label = str(
                row.get("attack_type", "None")
            ).strip().replace(" ", "_")

            logs.append(
                DatasetLog(
                    log_id=idx,
                    raw_text=raw,
                    is_anomaly=is_anomaly,
                    template_label=label,
                    group_label=label
                )
            )

        return logs
