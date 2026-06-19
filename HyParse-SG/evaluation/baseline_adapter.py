import re
import pandas as pd
from pathlib import Path

class BaselineAdapter:
    """
    Converts Drain, Spell, LogPPT, and LibreLog outputs into a common
    evaluation format:
        LineId | EventId | EventTemplate
    """

    SG_NUMERIC_KEYS = {
        "VOLTAGE",
        "FREQUENCY",
        "POWER_FLOW",
        "REACTIVE_POWER",
        "COMM_SIZE",
        "THREAT_PROB",
        "RISK_SCORE",
        "UNCERTAINTY",
        "TEMPORAL_ENTROPY",
        "SPECTRAL_ENERGY",
        "SPATIAL_CORR",
        "ATTACK_DETECTED",
    }

    SG_ID_KEYS = {
        "NODE",
        "NODE_ID",
    }

    @staticmethod
    def _clean_text(value):
        if pd.isna(value):
            return ""

        text = str(value).strip()
        text = re.sub(r"\s+", " ", text)
        return text

    @staticmethod
    def regex_to_template(regex_template):
        """
        Converts LibreLog RegexTemplate into ordinary log template format.
        """
        text = BaselineAdapter._clean_text(regex_template)

        # Convert regex wildcard groups to parser-style wildcard
        text = text.replace("(.*?)", "<*>")
        text = text.replace("(.+?)", "<*>")
        text = text.replace("(.*)", "<*>")

        # Remove common escaping from LibreLog regex output
        text = text.replace("\\=", "=")
        text = text.replace("\\-", "-")
        text = text.replace("\\.", ".")
        text = text.replace("\\+", "+")
        text = text.replace("\\/", "/")
        text = text.replace("\\_", "_")

        return text.strip()

    @staticmethod
    def normalize_sg_security_template(template):
        """
        Normalizes SG-Security templates for fair PA/GA comparison.
        Main purpose:
        - NODE=N12 -> NODE=<ID>
        - numeric fields -> <NUMBER>
        - preserve semantic fields
        """
        text = BaselineAdapter._clean_text(template)
        tokens = []

        for token in text.split():
            if "=" not in token:
                continue

            key, value = token.split("=", 1)
            key = key.strip().upper()
            value = value.strip()

            if key == "DATASET":
                continue

            if key in BaselineAdapter.SG_ID_KEYS:
                value = "<ID>"

            elif key in BaselineAdapter.SG_NUMERIC_KEYS:
                value = "<NUMBER>"

            else:
                value = (
                    value.replace(" ", "_")
                    .replace("-", "_")
                    .strip()
                )

            tokens.append(f"{key}={value}")

        return " ".join(tokens)

    @staticmethod
    def normalize_general_template(template):
        """
        General normalization for DNP3 and SWaT.
        """
        text = BaselineAdapter._clean_text(template)

        # Normalize whitespace only. Do not over-normalize DNP3/SWaT here.
        return text

    @staticmethod
    def normalize_template(template, dataset_name):
        dataset_name = dataset_name.upper()

        if "SG" in dataset_name or "SECURITY" in dataset_name:
            return BaselineAdapter.normalize_sg_security_template(template)

        return BaselineAdapter.normalize_general_template(template)

    @staticmethod
    def convert_parser_output(
        input_csv,
        output_csv,
        parser_name,
        dataset_name,
        template_col=None,
        event_id_col=None,
    ):
        """
        Converts one parser output file into standardized evaluation format.

        Parameters:
            input_csv:
                Parser output file.

            output_csv:
                Standardized output path.

            parser_name:
                drain, spell, logppt, librelog

            dataset_name:
                swat, dnp3, sg_security

            template_col:
                Optional explicit template column.

            event_id_col:
                Optional explicit event-id column.
        """
        input_csv = Path(input_csv)
        output_csv = Path(output_csv)

        df = pd.read_csv(input_csv)
        df.columns = [c.strip() for c in df.columns]

        parser_name = parser_name.lower()

        if template_col is None:
            if parser_name == "librelog":
                candidate_template_cols = [
                    "RegexTemplate",
                    "regex_template",
                    "EventTemplate",
                ]
            else:
                candidate_template_cols = [
                    "EventTemplate",
                    "event_template",
                    "Template",
                    "template",
                    "llm_refined_template",
                    "context_template",
                    "drain_template",
                ]
        else:
            candidate_template_cols = [template_col]

        selected_template_col = None

        for col in candidate_template_cols:
            if col in df.columns:
                selected_template_col = col
                break

        if selected_template_col is None:
            raise ValueError(
                f"No template column found in {input_csv}. "
                f"Available columns: {list(df.columns)}"
            )

        if event_id_col is None:
            candidate_event_cols = [
                "EventId",
                "event_id",
                "ClusterId",
                "cluster_id",
                "GroupId",
                "group_id",
            ]
        else:
            candidate_event_cols = [event_id_col]

        selected_event_col = None

        for col in candidate_event_cols:
            if col in df.columns:
                selected_event_col = col
                break

        templates = []

        for value in df[selected_template_col].tolist():
            if parser_name == "librelog":
                value = BaselineAdapter.regex_to_template(value)

            value = BaselineAdapter.normalize_template(
                value,
                dataset_name=dataset_name
            )

            templates.append(value)

        if "LineId" in df.columns:
            line_ids = df["LineId"].tolist()
        else:
            line_ids = list(range(1, len(df) + 1))

        if selected_event_col is not None:
            event_ids = df[selected_event_col].astype(str).tolist()
        else:
            event_ids = templates

        out_df = pd.DataFrame({
            "LineId": line_ids,
            "EventId": event_ids,
            "EventTemplate": templates,
        })

        output_csv.parent.mkdir(parents=True, exist_ok=True)
        out_df.to_csv(output_csv, index=False)

        print(f"[DONE] Saved standardized file: {output_csv}")
        print(f"[ROWS] {len(out_df)}")
        print(f"[TEMPLATE COLUMN] {selected_template_col}")
        print(f"[EVENT ID COLUMN] {selected_event_col}")