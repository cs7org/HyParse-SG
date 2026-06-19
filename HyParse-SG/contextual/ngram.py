from collections import defaultdict

class DeviceAwareNGramModel:

    """
    Device-aware N-gram model.
    Stores:
    - device-aware template sequences
    - contextual frequencies
    """
    def __init__(self, n=3):

        self.n = n

        self.counts = defaultdict(
            lambda: defaultdict(int)
        )

        self.context_totals = defaultdict(int)

    def _build_context(self, history):

        """
        Convert deque history
        into sliceable list.
        """

        history_list = list(history)

        return tuple(
            history_list[-(self.n - 1):]
        )

    def update(
        self,
        device,
        history,
        template
    ):

        context = self._build_context(history)

        key = (device, context)

        self.counts[key][template] += 1

        self.context_totals[key] += 1

    def get_count(
        self,
        device,
        history,
        template
    ):

        context = self._build_context(history)

        key = (device, context)

        return self.counts[key].get(template, 0)

    def get_max(
        self,
        device,
        history
    ):

        context = self._build_context(history)

        key = (device, context)

        if (
            key not in self.counts
            or not self.counts[key]
        ):
            return 1

        return max(
            self.counts[key].values()
        )