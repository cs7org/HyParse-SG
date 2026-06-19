import os
import csv
import re
from datetime import datetime

class ResultsWriter:
    """
    Writes parsing results and experiment metrics to CSV.
    """

    def __init__(self, output_dir="results/output"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _safe_filename(self, name):
        return re.sub(r"[^a-zA-Z0-9_.-]", "_", str(name))

    def _to_string(self, value):
        if value is None:
            return ""

        if isinstance(value, (list, tuple)):
            return " ".join(map(str, value))

        return str(value)

    def write_csv(
        self,
        before_llm,
        after_llm,
        total_time,
        model_name,
        dataset_name,
        metrics=None
    ):
        if metrics is None:
            metrics = {}

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        safe_dataset = self._safe_filename(dataset_name)
        safe_model = self._safe_filename(model_name)

        filename = f"{safe_dataset}_{safe_model}_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)

        header = [
            "log_id",
            "dataset",
            "raw_log",
            "normalized_tokens",

            "drain_template",
            "context_template",
            "DCS",
            "CCS",
            "FCS",

            "llm_refined_template",
            "is_anomaly",
            "is_refined",
            "predicted_anomaly", #
            "anomaly_reason", #

            "parsing_time",
            "total_processing_time",

            "PA",
            "GA",
            "Precision",
            "Recall",
            "F1",
            "CPR",
            "CDR",
            "CC",
            "PT",
            "MLL",
            "LLM_CR"
        ]

        rows_written = 0

        with open(
            filepath,
            mode="w",
            newline="",
            encoding="utf-8-sig"
        ) as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow(header)

            for before, after in zip(before_llm, after_llm):

                row = [
                    before.log_id,
                    getattr(before, "dataset", dataset_name),
                    before.raw_log,
                    self._to_string(
                        getattr(before, "normalized_tokens", [])
                    ),

                    self._to_string(before.template),
                    self._to_string(before.refined_template),
                    before.dcs.get("DCS", ""),
                    before.ccs.get("CCS", ""),
                    before.fcs,

                    self._to_string(after.refined_template),
                    getattr(before, "is_anomaly", False),
                    getattr(after, "is_refined", False),
                    getattr(before, "predicted_anomaly", False), #
                    getattr(before, "anomaly_reason", {}), #

                    getattr(before, "parsing_time", ""),
                    total_time,

                    metrics.get("PA", ""),
                    metrics.get("GA", ""),
                    metrics.get("Precision", ""),
                    metrics.get("Recall", ""),
                    metrics.get("F1", ""),
                    metrics.get("CPR", ""),
                    metrics.get("CDR", ""),
                    metrics.get("CC", ""),
                    metrics.get("PT", ""),
                    metrics.get("MLL", ""),
                    metrics.get("LLM_CR", "")
                ]

                if len(row) != len(header):
                    raise ValueError(
                        f"CSV row/header mismatch: "
                        f"{len(row)} values vs {len(header)} columns"
                    )

                writer.writerow(row)
                rows_written += 1

        print(f"[RESULTS SAVED] {filepath}")
        print(f"[ROWS WRITTEN] {rows_written}")


