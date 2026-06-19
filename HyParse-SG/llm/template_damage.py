import random

class TemplateDamager:
    """
    Controlled template degradation for LLM repair evaluation.
    """

    @staticmethod
    def damage(template, dataset_name="", rate=0.05):
        tokens = template.copy()

        if random.random() > rate:
            return tokens, False

        dataset_name = str(dataset_name).upper()

        if "DNP3" in dataset_name:
            return TemplateDamager._damage_dnp3(tokens)

        if "SWAT" in dataset_name:
            return TemplateDamager._damage_swat(tokens)

        if "SG" in dataset_name or "SECURITY" in dataset_name:
            return TemplateDamager._damage_sg_security(tokens)

        return TemplateDamager._damage_generic(tokens)

    @staticmethod
    def _damage_dnp3(tokens):
        damaged = tokens.copy()

        for i, token in enumerate(damaged):
            if token.startswith("REQ_FUNC="):
                damaged[i] = "REQ_FUNC=UNKNOWN"
                return damaged, True

            if token.startswith("RESP_FUNC="):
                damaged[i] = "RESP_FUNC=UNKNOWN"
                return damaged, True

            if token.startswith("EVENT="):
                damaged[i] = "EVENT=UNKNOWN"
                return damaged, True

            if token.startswith("SRC="):
                damaged[i] = "SRC=UNKNOWN"
                return damaged, True

            if token.startswith("DST="):
                damaged[i] = "DST=UNKNOWN"
                return damaged, True

        return TemplateDamager._damage_generic(tokens)

    @staticmethod
    def _damage_swat(tokens):
        damaged = tokens.copy()

        for i, token in enumerate(damaged):
            if token.startswith("STATUS="):
                damaged[i] = "STATUS=UNKNOWN"
                return damaged, True

            if token.startswith("FIT101="):
                damaged[i] = "FIT101=<*>"
                return damaged, True

            if token.startswith("LIT101="):
                damaged[i] = "LIT101=<*>"
                return damaged, True

            if token.startswith("P101="):
                damaged[i] = "P101=UNKNOWN"
                return damaged, True

            if token.startswith("EVENT="):
                damaged[i] = "EVENT=UNKNOWN"
                return damaged, True

        return TemplateDamager._damage_generic(tokens)

    @staticmethod
    def _damage_sg_security(tokens):
        damaged = tokens.copy()

        priority_prefixes = [
            "ATTACK_TYPE=",
            "POLICY=",
            "MTD=",
            "NODE=",
            "ACCESS=",
            "RISK_SCORE=",
            "THREAT_PROB=",
            "VOLTAGE=",
            "FREQUENCY=",
            "POWER_FLOW=",
        ]

        for prefix in priority_prefixes:
            for i, token in enumerate(damaged):
                if token.startswith(prefix):
                    key = token.split("=", 1)[0]

                    if key == "ATTACK_TYPE":
                        damaged[i] = "ATTACK_TYPE=UNKNOWN"
                    elif key == "NODE":
                        damaged[i] = "NODE=UNKNOWN"
                    elif key in {"RISK_SCORE", "THREAT_PROB"}:
                        damaged[i] = f"{key}=<*>"
                    else:
                        damaged[i] = f"{key}=UNKNOWN"

                    return damaged, True

        damaged.append("<*>")
        return damaged, True

    @staticmethod
    def _damage_generic(tokens):
        damaged = tokens.copy()

        for i, token in enumerate(damaged):
            if "=" in token:
                key = token.split("=", 1)[0]
                damaged[i] = f"{key}=UNKNOWN"
                return damaged, True

        damaged.append("<*>")
        return damaged, True