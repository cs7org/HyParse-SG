import pandas as pd
from dataset.base import DatasetLog

class DNP3Loader:
    """
    Robust loader for DNP3 datasets.
    Converts each row into a canonical DNP3 log message.
    """

    def __init__(self, file_path, limit=None):
        self.file_path = file_path
        self.limit = limit

    def _normalize_col(self, col):
        return (
            str(col)
            .strip()
            .lower()
            .replace("_", "")
            .replace("-", "")
            .replace(" ", "")
            .replace("/", "")
        )

    def _build_column_map(self, df):
        return {
            self._normalize_col(col): col
            for col in df.columns
        }

    def _safe(self, value):
        try:
            if pd.isna(value):
                return "UNKNOWN"
            value = str(value).strip()
            if value == "":
                return "UNKNOWN"
            return value.replace(" ", "_")
        except Exception:
            return "UNKNOWN"

    def _get(self, row, colmap, candidates, default="UNKNOWN"):
        for candidate in candidates:
            key = self._normalize_col(candidate)
            if key in colmap:
                return self._safe(row[colmap[key]])
        return default

    def _infer_role(self, src_port, dst_port):
        if str(dst_port) == "20000":
            return "MASTER_TO_OUTSTATION"
        if str(src_port) == "20000":
            return "OUTSTATION_TO_MASTER"
        return "UNKNOWN"

    def _normalize_event(self, value):
        value = self._safe(value)

        if value.upper() in ["BENIGN", "NORMAL", "0"]:
            return "NORMAL"

        return value.upper()

    def _build_log(self, row, colmap):
        src_ip = self._get(
            row,
            colmap,
            [
                "source IP",
                "src ip",
                "Src IP",
                "Source IP",
                "sourceIP",
                "srcIP"
            ]
        )

        dst_ip = self._get(
            row,
            colmap,
            [
                "destination IP",
                "dst ip",
                "Dst IP",
                "Destination IP",
                "destinationIP",
                "dstIP"
            ]
        )

        src_port = self._get(
            row,
            colmap,
            [
                "source port",
                "src port",
                "Src Port",
                "Source Port",
                "sourcePort",
                "srcPort"
            ]
        )

        dst_port = self._get(
            row,
            colmap,
            [
                "destination port",
                "dst port",
                "Dst Port",
                "Destination Port",
                "destinationPort",
                "dstPort"
            ]
        )

        proto = self._get(
            row,
            colmap,
            [
                "protocol",
                "Protocol",
                "proto"
            ]
        )

        role = self._infer_role(src_port, dst_port)

        link_func = self._get(
            row,
            colmap,
            [
                "LINK_FUNC",
                "link_func",
                "ctl_prifunc",
                "ctl prifunc",
                "mostCommonLINK_FUNC_CODE",
                "most common link func code"
            ],
            default="UNKNOWN"
        )

        req_func = self._get(
            row,
            colmap,
            [
                "mostCommonREQ_FUNC_CODE",
                "most common req func code",
                "REQ_FUNC",
                "REQ_FUNC_CODE",
                "req func",
                "request function"
            ],
            default="UNKNOWN"
        )

        resp_func = self._get(
            row,
            colmap,
            [
                "mostCommonRESP_FUNC_CODE",
                "most common resp func code",
                "RESP_FUNC",
                "RESP_FUNC_CODE",
                "resp func",
                "response function"
            ],
            default="UNKNOWN"
        )

        event = self._get(
            row,
            colmap,
            [
                "Label",
                "label",
                "Event",
                "event",
                "EVENT",
                "attack_type",
                "attack type"
            ],
            default="NORMAL"
        )

        event = self._normalize_event(event)

        return (
            f"SRC={src_ip} "
            f"DST={dst_ip} "
            f"SPORT={src_port} "
            f"DPORT={dst_port} "
            f"PROTO={proto} "
            #f"DNP3_ROLE={role} "
            #f"LINK_FUNC={link_func} "
            f"REQ_FUNC={req_func} "
            f"RESP_FUNC={resp_func} "
            f"EVENT={event}"
        )

    def load(self):
        df = pd.read_csv(self.file_path)
        df.columns = [str(c).strip() for c in df.columns]

        print("\n[DNP3 DATASET COLUMNS]")
        print(list(df.columns))

        colmap = self._build_column_map(df)

        print("\n[DNP3 NORMALIZED COLUMN MAP]")
        print(colmap)

        if self.limit:
            df = df.head(self.limit)

        logs = []

        for idx, row in df.iterrows():
            raw = self._build_log(row, colmap)

            event = raw.split("EVENT=", 1)[1]

            is_anomaly = event.upper() not in [
                "NORMAL",
                "BENIGN",
                "0"
            ]

            logs.append(
                DatasetLog(
                    log_id=idx + 1,
                    raw_text=raw,
                    is_anomaly=is_anomaly
                )
            )

        return logs
    