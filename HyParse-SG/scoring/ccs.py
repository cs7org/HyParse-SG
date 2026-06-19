class DeviceTransitionTracker:
    """
    Tracks device-to-device transitions.
    """
    def __init__(self):
        self.transitions = {}
        self.max_val = 1

    def update(self, previous_device, current_device):
        if previous_device is None:
            return

        key = (previous_device, current_device)

        self.transitions[key] = (
            self.transitions.get(key, 0) + 1
        )

        self.max_val = max(
            self.max_val,
            self.transitions[key]
        )

    def get(self, previous_device, current_device):
        return self.transitions.get(
            (previous_device, current_device),
            0
        )

class CCSScorer:

    def __init__(self, model, tracker, gamma=0.7):
        self.model = model
        self.tracker = tracker
        self.gamma = gamma
        self.prev_device = None

    def compute(self, device, history, template):
        """
        Compute contextual confidence before updating transition state.
        """

        freq = self.model.get_count(
            device,
            history,
            template
        )

        max_freq = self.model.get_max(
            device,
            history
        )


        danf = freq / max_freq if max_freq else 0.0

        if self.prev_device is None:
            dtc = 1.0
        else:
            transition_freq = self.tracker.get(
                self.prev_device,
                device
            )


            dtc = (
                transition_freq / self.tracker.max_val
                if self.tracker.max_val > 0
                else 0.0
            )

        ccs = (
            self.gamma * danf
            + (1 - self.gamma) * dtc
        )

        # Update transition state after scoring
        self.tracker.update(
            self.prev_device,
            device
        )

        self.prev_device = device

        return {
            "CCS": ccs,
            "DANF": danf,
            "DTC": dtc
        }