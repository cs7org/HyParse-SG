class DecisionEngine:
    """
        Template-level decision engine.
        Decides whether accept template or send to LLM refinement.
        """

    def __init__(self, threshold, refiner=None):

        self.threshold = threshold

        self.refiner = refiner

    def process(self, buffer):

        results = []

        while not buffer.is_empty():

            candidate = buffer.pop()

            # LOW CONFIDENCE → LLM

            if (
                    (
                            candidate.fcs < self.threshold
                            or getattr(candidate, "template_damaged", False)
                    )
                    and self.refiner
            ):

                candidate = self.refiner.refine(candidate)

            # ACCEPT TEMPLATE

            results.append(candidate)

        return results