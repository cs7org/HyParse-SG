from dataclasses import dataclass, field

@dataclass
class DatasetLog:
    """
    Unified internal dataset representation.
    """
    log_id: int # unique log identifier
    raw_text: str # raw semantic event string
    #template: str = None
    #group_id: int = None
    is_anomaly: bool = False # anomaly label
    template_label: str = None # expected template label
    group_label: int = None  # expected grouping label
    tokens: list = field(default_factory=list) # tokens generated during preprocessing