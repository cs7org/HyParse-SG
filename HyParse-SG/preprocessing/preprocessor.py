import re
from dataclasses import dataclass

@dataclass
class PreprocessedLog:
    log_id: int
    raw_text: str
    tokens: list
    is_anomaly: bool = False

class SGPreprocessor:
    """
    Generic Smart Grid key-value preprocessor.

    """

    SEMANTIC_KEYS = {
        "EVENT",
        "LABEL",
        "ATTACK_TYPE",
        "POLICY",
        "MTD",
        "ACCESS",
        "REQ_FUNC",
        "RESP_FUNC",
        "LINK_FUNC",
        "DNP3_ROLE",
        "ATTACK_DETECTED",
        "STATUS"
    }

    ID_KEYS = {
        "NODE",
        "NODE_ID",
        "DEVICE",
        "DEVICE_ID",
        "DATASET",
    }

    IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    NUMBER_REGEX = re.compile(r"^-?\d+(\.\d+)?$")

    def preprocess(self, log):
        raw_text = getattr(log, "raw_text", str(log))
        log_id = getattr(log, "log_id", None)
        is_anomaly = getattr(log, "is_anomaly", False)

        tokens = [
            self._normalize_token(token)
            for token in str(raw_text).strip().split()
        ]

        return PreprocessedLog(
            log_id=log_id,
            raw_text=raw_text,
            tokens=tokens,
            is_anomaly=is_anomaly
        )

    def _normalize_token(self, token):
        token = str(token).strip()

        if "=" not in token:
            return token

        key, value = token.split("=", 1)

        key = key.strip()
        value = value.strip()

        key_upper = key.upper()

        if value == "" or value.upper() in {"NAN", "NONE", "NULL"}:
            return f"{key}=UNKNOWN"

        if key_upper in self.SEMANTIC_KEYS:
            return f"{key}={value}"

        if key_upper in self.ID_KEYS:
            return f"{key}=<ID>"

        if self.IP_REGEX.match(value):
            return f"{key}=<IP>"

        if self.NUMBER_REGEX.match(value):
            return f"{key}=<NUMBER>"

        if value.upper() in {
            "ON",
            "OFF",
            "OPEN",
            "CLOSED",
            "TRUE",
            "FALSE",
            "LOGIN",
            "LOGOUT",
            "READ",
            "WRITE",
        }:
            return f"{key}=<STATE>"

        return f"{key}=<VALUE>"