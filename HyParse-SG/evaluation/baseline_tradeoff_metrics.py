import ast
import re
import pandas as pd

class BaselineTradeoffMetrics:
    """
    Evaluates parser output against standardized evaluation files.
    Expected standardized format:
    LineId | EventId | EventTemplate
    HyParse-SG raw result files are also supported if they contain:
    llm_refined_template / context_template / drain_template
    """
    STRUCTURAL_IP_KEYS = {
        "SRC",
        "DST",
        "SOURCE_IP",
        "DESTINATION_IP",
        "FRAME_SRC",
        "FRAME_DST",
    }

    STRUCTURAL_NUMBER_KEYS = {
        "SPORT",
        "DPORT",
        "PROTO",
        "SOURCE_PORT",
        "DESTINATION_PORT",
        "PROTOCOL",

        "VOLTAGE",
        "VOLTAGE_LEVEL",
        "FREQUENCY",
        "FREQUENCY_SIGNAL",
        "POWER_FLOW",
        "REACTIVE_POWER",
        "COMM_SIZE",
        "COMMUNICATION_LOG_SIZE",
        "THREAT_PROB",
        "THREAT_PROBABILITY",
        "RISK_SCORE",
        "UNCERTAINTY",
        "TEMPORAL_ENTROPY",
        "SPECTRAL_ENERGY",
        "SPATIAL_CORR",
        "SPATIAL_CORRELATION",
        "ATTACK_DETECTED",
    }

    @staticmethod
    def normalize_dnp3_event(value):
        value = str(value).strip().upper()

        event_map = {
            "DNP3_INFO": "INFO",
            "DNP3_ENUMERATE": "INFO",

            "COLD_RESTART": "RESTART",
            "WARM_RESTART": "RESTART",

            "STOP_APP": "APP_CONTROL",
            "START_APP": "APP_CONTROL",

            "DISABLE_UNSOLICITED": "UNSOLICITED_CONTROL",
            "ENABLE_UNSOLICITED": "UNSOLICITED_CONTROL",

            "INIT_DATA": "CONTROL",
            "REPLAY": "ATTACK",
            "ARP_POISONING": "ATTACK",

            "NORMAL": "NORMAL",
        }

        return event_map.get(value, value)

    @staticmethod
    def structural_template(template):
        template = BaselineTradeoffMetrics.canonicalize_template(template)

        keep_keys = {
            "SRC",
            "DST",
            "SPORT",
            "DPORT",
            "PROTO",
            "REQ_FUNC",
            "RESP_FUNC"
        }

        filtered = []

        for token in template.split():
            if "=" not in token:
                continue

            key, value = token.split("=", 1)

            if key in keep_keys:
                filtered.append(f"{key}={value}")

        return " ".join(sorted(filtered))

    @staticmethod
    def structural_parsing_accuracy(predicted_templates, ground_truth_templates):
        total = len(ground_truth_templates)
        correct = 0

        for pred, gt in zip(predicted_templates, ground_truth_templates):

            pred_struct = BaselineTradeoffMetrics.structural_template(pred)
            gt_struct = BaselineTradeoffMetrics.structural_template(gt)

            if pred_struct == gt_struct:
                correct += 1

        return correct / total if total else 0.0

    def normalize_template(template):
        if pd.isna(template):
            return ""

        text = str(template).strip()

        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = ast.literal_eval(text)
                if isinstance(parsed, list):
                    text = " ".join(str(x) for x in parsed)
            except Exception:
                pass

        text = re.sub(r"\s+", " ", text)

        # Repair baseline template styles.
        text = re.sub(r"([A-Za-z0-9_]+)\s+<\*>", r"\1=<*>", text)
        text = re.sub(r"([A-Za-z0-9_]+)\s+<NUMBER>", r"\1=<NUMBER>", text)
        text = re.sub(r"([A-Za-z0-9_]+)\s+<IP>", r"\1=<IP>", text)
        text = re.sub(r"([A-Za-z0-9_]+)\s+<ID>", r"\1=<ID>", text)

        # Repair LibreLog-style regex templates.
        text = text.replace("(.*?)", "<*>")
        text = text.replace("(.+?)", "<*>")
        text = text.replace("(.*)", "<*>")
        text = text.replace("\\", "")

        return text.strip()

    @staticmethod
    def _kv_tokens(template):
        """
        Converts template into KEY=value tokens.
        Also repairs split multi-word values
        """
        text = BaselineTradeoffMetrics.normalize_template(template)
        raw_tokens = text.split()

        tokens = []

        for token in raw_tokens:
            if "=" in token:
                tokens.append(token)
            else:
                if tokens and "=" in tokens[-1]:
                    tokens[-1] = tokens[-1] + "_" + token

        return tokens

    @staticmethod
    def canonicalize_template(template):
        text_tokens = BaselineTradeoffMetrics._kv_tokens(template)

        sg_number_keys = {
            "VOLTAGE",
            "VOLTAGE_LEVEL",
            "FREQUENCY",
            "FREQUENCY_SIGNAL",
            "POWER_FLOW",
            "REACTIVE_POWER",
            "COMM_SIZE",
            "COMMUNICATION_LOG_SIZE",
            "THREAT_PROB",
            "THREAT_PROBABILITY",
            "RISK_SCORE",
            "UNCERTAINTY",
            "TEMPORAL_ENTROPY",
            "SPECTRAL_ENERGY",
            "SPATIAL_CORR",
            "SPATIAL_CORRELATION",
            "ATTACK_DETECTED",
        }

        sg_id_keys = {
            "NODE",
            "NODE_ID",
        }

        sg_semantic_keys = {
            "ACCESS",
            "ACCESS_BEHAVIOR",
            "ATTACK_TYPE",
            "POLICY",
            "POLICY_ACTION",
            "MTD",
            "MTD_STRATEGY_USED",
        }

        tokens = []

        for token in text_tokens:
            if "=" not in token:
                continue

            key, value = token.split("=", 1)

            key = key.strip().upper()
            value = value.strip()

            if key in {"DATASET", "EVENT", "STATUS"}:
                continue

            value_upper = value.upper()

            # Normalize placeholders
            if value_upper in {
                "<IP>",
                "<NUMBER>",
                "<FLOAT>",
                "<STATE>",
                "<ID>",
                "<VALUE>",
                "<*>",
                "UNKNOWN",
                "<DNP3_FUNC>",
            }:
                value = value_upper

            # SG identifiers
            elif key in sg_id_keys:
                value = "<ID>"

            # SG numeric / measurement fields
            elif key in sg_number_keys:
                value = "<NUMBER>"

            # SG semantic fields: preserve categorical meaning
            elif key in sg_semantic_keys:
                value = value.replace("-", "_")
                value = value.replace(" ", "_")
                value = value.upper()

            # DNP3 IP fields
            elif key in BaselineTradeoffMetrics.STRUCTURAL_IP_KEYS:
                value = "<IP>"

            # DNP3 numeric structural fields
            elif key in BaselineTradeoffMetrics.STRUCTURAL_NUMBER_KEYS:
                value = "<NUMBER>"

            # Concrete DNP3 function codes are generalized
            elif key in {"REQ_FUNC", "RESP_FUNC", "LINK_FUNC"}:
                value = "<DNP3_FUNC>"

            # Generic numbers
            elif re.fullmatch(r"-?\d+(\.\d+)?", value):
                value = "<NUMBER>"

            # Generic IPs
            elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
                value = "<IP>"

            else:
                value = value.replace("-", "_")
                value = value.replace(" ", "_")
                value = value.upper()

            tokens.append(f"{key}={value}")

        return " ".join(sorted(tokens))

    @staticmethod
    def sg_security_signature(template):
        """
        SG-Security semantic PA signature.
        """
        tokens = BaselineTradeoffMetrics._kv_tokens(template)

        keep_keys = {
            "ACCESS",
            "ACCESS_BEHAVIOR",
            "ATTACK_TYPE",
            "POLICY",
            "POLICY_ACTION",
            "MTD",
            "MTD_STRATEGY_USED",
        }

        aliases = {
            "ACCESS_BEHAVIOR": "ACCESS",
            "POLICY_ACTION": "POLICY",
            "MTD_STRATEGY_USED": "MTD",
        }

        fields = {}

        for token in tokens:
            if "=" not in token:
                continue

            key, value = token.split("=", 1)

            key = key.strip().upper()
            key = aliases.get(key, key)

            if key not in keep_keys and key not in aliases.values():
                continue

            value = (
                value.strip()
                .upper()
                .replace("-", "_")
                .replace(" ", "_")
            )

            fields[key] = value

        return "|".join(
            f"{key}={fields[key]}"
            for key in sorted(fields)
        )

    @staticmethod
    def canonicalize_event_id(event_id):
        if pd.isna(event_id):
            return ""

        text = str(event_id).strip().upper()
        text = re.sub(r"\s+", " ", text)

        parts = []

        for part in text.split("|"):
            if "=" not in part:
                parts.append(part)
                continue

            key, value = part.split("=", 1)

            if key in {"EVENT", "STATUS"}:
                value = BaselineTradeoffMetrics.normalize_dnp3_event(value)

            if key in {"REQ", "RESP", "REQ_FUNC", "RESP_FUNC"}:
                value = "<DNP3_FUNC>"

            parts.append(f"{key}={value}")

        return "|".join(parts)

    @staticmethod
    def load_predicted_templates(predicted_csv, pred_template_col=None):
        df = pd.read_csv(predicted_csv)
        df.columns = [c.strip() for c in df.columns]

        if pred_template_col is not None:
            candidate_cols = [pred_template_col, "EventTemplate"]
        else:
            candidate_cols = [
                "EventTemplate",
                "llm_refined_template",
                "context_template",
                "drain_template",
            ]

        for col in candidate_cols:
            if col in df.columns:
                out_df = pd.DataFrame({
                    "LineId": (
                        df["LineId"].tolist()
                        if "LineId" in df.columns
                        else range(1, len(df) + 1)
                    ),
                    "EventTemplate": df[col].astype(str)
                })

                if "EventId" in df.columns:
                    out_df["EventId"] = df["EventId"].astype(str)
                else:
                    out_df["EventId"] = out_df["EventTemplate"].apply(
                        BaselineTradeoffMetrics.canonicalize_template
                    )

                return out_df[["LineId", "EventId", "EventTemplate"]]

        raise ValueError(
            f"No usable predicted-template column found in {predicted_csv}. "
            f"Available columns: {list(df.columns)}"
        )

    @staticmethod
    def load_ground_truth_templates(ground_truth_csv):
        df = pd.read_csv(ground_truth_csv)
        df.columns = [c.strip() for c in df.columns]

        if "EventTemplate" not in df.columns:
            raise ValueError(
                "Ground truth CSV must contain 'EventTemplate'. "
                f"Available columns: {list(df.columns)}"
            )

        if "LineId" not in df.columns:
            df["LineId"] = range(1, len(df) + 1)

        if "EventId" not in df.columns:
            df["EventId"] = df["EventTemplate"].apply(
                BaselineTradeoffMetrics.canonicalize_template
            )

        return df[["LineId", "EventId", "EventTemplate"]]

    @staticmethod
    def _normalize_value(key, value):
        key = str(key).upper().strip()
        value = str(value).upper().strip()

        value = value.replace("<*>.<*>", "<NUMBER>")
        value = value.replace("<*>", "<WILDCARD>")
        value = value.replace("<NUM>", "<NUMBER>")

        if re.fullmatch(r"-?\d+(\.\d+)?", value):
            return "<NUMBER>"

        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
            return "<IP>"

        if key in {
            "SRC", "DST", "SOURCE_IP", "DESTINATION_IP",
            "FRAME_SRC", "FRAME_DST"
        }:
            if value in {"<WILDCARD>", "<IP>"}:
                return "<IP>"

        if key in {
            "SPORT", "DPORT", "PROTO",
            "VOLTAGE", "FREQUENCY", "POWER_FLOW",
            "REACTIVE_POWER", "COMM_SIZE", "THREAT_PROB",
            "RISK_SCORE", "UNCERTAINTY", "TEMPORAL_ENTROPY",
            "SPECTRAL_ENERGY", "SPATIAL_CORR",
            "FIT101", "LIT101", "P101", "P102",
            "AIT202", "AIT203", "FIT201", "DPIT301", "AIT503",
            "ATTACK_DETECTED"
        }:
            if value in {"<WILDCARD>", "<NUMBER>"}:
                return "<NUMBER>"

        if key in {"NODE", "NODE_ID"}:
            if value in {"<WILDCARD>", "<ID>"}:
                return "<ID>"

        return value.replace("-", "_").replace(" ", "_")

    def _template_fields(template):
        text = BaselineTradeoffMetrics.normalize_template(template)

        key_aliases = {
            "FLOW_DURATION": "FLOW_DURATION",
            "FLOW DURATION": "FLOW_DURATION",

            "TOT_FWD_PKTS": "TOT_FWD_PKTS",
            "TOT FWD PKTS": "TOT_FWD_PKTS",

            "TOT_BWD_PKTS": "TOT_BWD_PKTS",
            "TOT BWD PKTS": "TOT_BWD_PKTS",

            "FLOW_BYTS/S": "FLOW_BYTS_S",
            "FLOW BYTS/S": "FLOW_BYTS_S",
            "FLOW_BYTES/S": "FLOW_BYTS_S",

            "FLOW_PKTS/S": "FLOW_PKTS_S",
            "FLOW PKTS/S": "FLOW_PKTS_S",

            "SRC": "SRC",
            "DST": "DST",
            "SPORT": "SPORT",
            "DPORT": "DPORT",
            "PROTO": "PROTO",
            "REQ_FUNC": "REQ_FUNC",
            "RESP_FUNC": "RESP_FUNC",

            "NODE": "NODE",
            "ACCESS": "ACCESS",
            "ATTACK_TYPE": "ATTACK_TYPE",
            "POLICY": "POLICY",
            "MTD": "MTD",
            "ATTACK_DETECTED": "ATTACK_DETECTED",

            "VOLTAGE": "VOLTAGE",
            "FREQUENCY": "FREQUENCY",
            "POWER_FLOW": "POWER_FLOW",
            "REACTIVE_POWER": "REACTIVE_POWER",
            "COMM_SIZE": "COMM_SIZE",
            "THREAT_PROB": "THREAT_PROB",
            "RISK_SCORE": "RISK_SCORE",
            "UNCERTAINTY": "UNCERTAINTY",
            "TEMPORAL_ENTROPY": "TEMPORAL_ENTROPY",
            "SPECTRAL_ENERGY": "SPECTRAL_ENERGY",
            "SPATIAL_CORR": "SPATIAL_CORR",

            "FIT101": "FIT101",
            "LIT101": "LIT101",
            "P101": "P101",
            "P102": "P102",
            "AIT202": "AIT202",
            "AIT203": "AIT203",
            "FIT201": "FIT201",
            "DPIT301": "DPIT301",
            "AIT503": "AIT503",
            "EVENT": "EVENT",
            "STATUS": "STATUS",
        }

        fields = {}

        pattern = re.compile(
            r"([A-Za-z0-9_ /]+?)=([^=]+?)(?=\s+[A-Za-z0-9_ /]+?=|$)"
        )

        for match in pattern.finditer(text):
            raw_key = match.group(1).strip().upper()
            value = match.group(2).strip()

            raw_key = raw_key.replace("_", " ")

            key = key_aliases.get(raw_key, raw_key.replace(" ", "_"))

            if key == "DATASET":
                continue

            fields[key] = BaselineTradeoffMetrics._normalize_value(
                key,
                value
            )

        return fields

    @staticmethod
    def _token_set(template):
        text = BaselineTradeoffMetrics.normalize_template(template)
        text = text.upper()
        text = text.replace("<*>", "<WILDCARD>")
        text = re.sub(r"-?\d+(\.\d+)?", "<NUMBER>", text)
        text = re.sub(r"\d{1,3}(\.\d{1,3}){3}", "<IP>", text)

        tokens = set()

        for token in re.split(r"\s+", text):
            token = token.strip()
            if not token or token == "DATASET":
                continue
            tokens.add(token)

        return tokens

    @staticmethod
    def _token_overlap_score(pred, gt):
        pred_tokens = BaselineTradeoffMetrics._token_set(pred)
        gt_tokens = BaselineTradeoffMetrics._token_set(gt)

        if not gt_tokens:
            return 0.0

        return len(pred_tokens & gt_tokens) / len(gt_tokens)

    @staticmethod
    def _field_score(pred, gt):
        pred_fields = BaselineTradeoffMetrics._template_fields(pred)
        gt_fields = BaselineTradeoffMetrics._template_fields(gt)

        if not gt_fields:
            return 0.0

        matched = 0

        for key, gt_value in gt_fields.items():
            pred_value = pred_fields.get(key)

            if pred_value is None:
                continue

            if pred_value == gt_value:
                matched += 1

            elif pred_value == "<WILDCARD>":
                matched += 1

        return matched / len(gt_fields)

    @staticmethod
    def _is_sg_security_template(template):
        text = BaselineTradeoffMetrics.normalize_template(template).upper()

        return (
                "ATTACK_TYPE" in text
                or "POLICY" in text
                or "MTD" in text
                or "ATTACK_DETECTED" in text
        )

    @staticmethod
    def _sg_security_presence_score(pred, gt):
        pred_text = BaselineTradeoffMetrics.normalize_template(pred).upper()
        gt_text = BaselineTradeoffMetrics.normalize_template(gt).upper()

        expected_keys = [
            "NODE",
            "ACCESS",
            "ATTACK_TYPE",
            "POLICY",
            "MTD",
            "ATTACK_DETECTED",
        ]

        gt_keys = [
            key for key in expected_keys
            if f"{key}=" in gt_text
        ]

        if not gt_keys:
            return 0.0

        matched = sum(
            1 for key in gt_keys
            if f"{key}=" in pred_text
        )

        return matched / len(gt_keys)

    @staticmethod
    def parsing_accuracy(predicted_templates, ground_truth_templates):
        total = len(ground_truth_templates)
        total_score = 0.0

        for pred, gt in zip(predicted_templates, ground_truth_templates):
            field_score = BaselineTradeoffMetrics._field_score(pred, gt)
            token_score = BaselineTradeoffMetrics._token_overlap_score(pred, gt)

            total_score += max(field_score, token_score)

        return total_score / total if total else 0.0

    @staticmethod
    def grouping_accuracy(predicted_event_ids, ground_truth_event_ids, mode="cluster"):
        total = len(ground_truth_event_ids)

        if total == 0:
            return 0.0

        predicted_groups = {}

        for idx, pred_id in enumerate(predicted_event_ids):
            pred_id = BaselineTradeoffMetrics.canonicalize_event_id(pred_id)
            predicted_groups.setdefault(pred_id, []).append(idx)

        correct = 0

        for group_indices in predicted_groups.values():
            gt_labels = [
                BaselineTradeoffMetrics.canonicalize_event_id(
                    ground_truth_event_ids[i]
                )
                for i in group_indices
            ]

            counts = {}

            for label in gt_labels:
                counts[label] = counts.get(label, 0) + 1

            correct += max(counts.values())

        return correct / total

    @staticmethod
    def parsing_throughput(total_logs, total_time):
        return total_logs / total_time if total_time > 0 else 0.0

    @staticmethod
    def mean_log_latency(total_time, total_logs):
        return total_time / total_logs if total_logs > 0 else 0.0

    @staticmethod
    def debug_first_mismatch(pred_df, gt_df):
        for i, (pred, gt) in enumerate(
            zip(
                pred_df["EventTemplate"].tolist(),
                gt_df["EventTemplate"].tolist()
            )
        ):
            pred_can = BaselineTradeoffMetrics.canonicalize_template(pred)
            gt_can = BaselineTradeoffMetrics.canonicalize_template(gt)

            if pred_can != gt_can:
                print("\n[PA MISMATCH DEBUG]")
                print(f"LineId: {pred_df.loc[i, 'LineId']}")
                print("PRED RAW:", pred)
                print("GT RAW:  ", gt)
                print("PRED CAN:", pred_can)
                print("GT CAN:  ", gt_can)
                break

    @staticmethod
    def evaluate_from_files(
        method_name,
        predicted_csv,
        ground_truth_csv,
        total_time,
        pred_template_col=None,
        debug=False
    ):
        pred_df = BaselineTradeoffMetrics.load_predicted_templates(
            predicted_csv,
            pred_template_col=pred_template_col
        )

        gt_df = BaselineTradeoffMetrics.load_ground_truth_templates(
            ground_truth_csv
        )

        if len(pred_df) != len(gt_df):
            raise ValueError(
                f"Length mismatch for {method_name}: "
                f"predicted={len(pred_df)}, ground_truth={len(gt_df)}"
            )

        pred_df = pred_df.sort_values("LineId").reset_index(drop=True)
        gt_df = gt_df.sort_values("LineId").reset_index(drop=True)

        pa = BaselineTradeoffMetrics.parsing_accuracy(
            pred_df["EventTemplate"].tolist(),
            gt_df["EventTemplate"].tolist()
        )

        spa = BaselineTradeoffMetrics.structural_parsing_accuracy(
            pred_df["EventTemplate"].tolist(),
            gt_df["EventTemplate"].tolist()
        )

        if "DNP3" in method_name.upper():
            pred_group_ids = [
                BaselineTradeoffMetrics.canonicalize_template(t)
                for t in pred_df["EventTemplate"].tolist()
            ]

            gt_group_ids = [
                BaselineTradeoffMetrics.canonicalize_template(t)
                for t in gt_df["EventTemplate"].tolist()
            ]

            ga = BaselineTradeoffMetrics.grouping_accuracy(
                pred_group_ids,
                gt_group_ids,
                mode="row"
            )

        else:
            ga = BaselineTradeoffMetrics.grouping_accuracy(
                pred_df["EventId"].tolist(),
                gt_df["EventId"].tolist(),
                mode="cluster"
            )

        if debug:
            BaselineTradeoffMetrics.debug_first_mismatch(pred_df, gt_df)

        total_logs = len(gt_df)

        pt = BaselineTradeoffMetrics.parsing_throughput(
            total_logs,
            total_time
        )

        mll = BaselineTradeoffMetrics.mean_log_latency(
            total_time,
            total_logs
        )

        return {
            "Method": method_name,
            "PA": pa,
            "SPA": spa,
            "GA": ga,
            "PT": pt,
            "MLL": mll,
            "TotalLogs": total_logs,
            "TotalTime": total_time
        }