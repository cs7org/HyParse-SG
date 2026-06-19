class FCSCombiner:

    def __init__(self, alpha=0.67):
        self.alpha = alpha

    def compute(self, dcs, ccs):
        return self.alpha * dcs + (1 - self.alpha) * ccs