import re

class TokenClassifier:
    """
    Generic token classifier for Smart-Grid key-value logs.
    """

    SEMANTIC_PREFIXES = (
        "EVENT=",
        "LABEL=",
        "ATTACK_TYPE=",
        "POLICY=",
        "MTD=",
        "ACCESS=",
        "REQ_FUNC=",
        "RESP_FUNC=",
        "LINK_FUNC=",
        "DNP3_ROLE=",
        "ATTACK_DETECTED=",
    )

    def classify(self, token):
        if token is None:
            return "UNKNOWN"

        token = str(token)

        if token.startswith(self.SEMANTIC_PREFIXES):
            return "SEMANTIC"

        if token.endswith("=<IP>"):
            return "IP"

        if token.endswith("=<NUMBER>"):
            return "NUMBER"

        if token.endswith("=<STATE>"):
            return "STATE"

        if token.endswith("=<ID>"):
            return "ID"

        if token.endswith("=<VALUE>"):
            return "VALUE"

        if token.endswith("=UNKNOWN"):
            return "UNKNOWN"

        if "=" in token:
            return "KEY_VALUE"

        return "TEXT"


class TokenWeighter:
    """
    Weights used by confidence scoring.
    Semantic SG fields are intentionally weighted higher.
    """

    def __init__(self):
        self.weights = {
            "SEMANTIC": 3.0,
            "STATE": 2.0,
            "ID": 1.8,
            "IP": 1.5,
            "KEY_VALUE": 1.3,
            "VALUE": 1.2,
            "NUMBER": 1.0,
            "TEXT": 1.0,
            "UNKNOWN": 0.3,
        }

    def get_weight(self, token_type):
        return self.weights.get(token_type, 1.0)
