class DeviceExtractor:
    """
    Extracts a device/context entity from normalized tokens.
    """
    def __init__(self, classifier):
        self.classifier = classifier

    def extract(self, tokens):
        src = None
        dst = None

        for token in tokens:
            if token.startswith("SRC="):
                src = token
            elif token.startswith("DST="):
                dst = token

        if src and dst:
            return f"{src}->{dst}"

        for token in tokens:
            if token.startswith(("FIT", "LIT", "AIT", "P", "MV")):
                return token.split("=")[0]

        return "UNKNOWN"