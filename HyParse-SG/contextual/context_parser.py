from collections import deque
from contextual.device import DeviceExtractor
from contextual.ngram import DeviceAwareNGramModel

class ContextualParser:
    """
    Device-aware contextual parser.
    - process() extracts contextual representation
    - update_model() is called after CCS calculation
    """
    def __init__(self, classifier, n=3):
        self.model = DeviceAwareNGramModel(n)
        self.history = deque(maxlen=50)
        self.devices = deque(maxlen=50)
        self.extractor = DeviceExtractor(classifier)

    def process(self, log, template):
        device = self.extractor.extract(log.tokens)

        refined_template = template.tokens.copy()

        return {
            "refined_template": refined_template,
            "device": device
        }

    def update_model(self, device, refined_template):
        template_key = tuple(refined_template)

        self.model.update(
            device,
            self.history,
            template_key
        )

        self.history.append(template_key)

        self.devices.append(device)