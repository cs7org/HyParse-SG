from dataclasses import dataclass

@dataclass
class TemplateCandidate:
    log_id: int
    raw_log: str
    template: list
    refined_template: list
    device: str
    dcs: dict
    ccs: dict
    fcs: float
    is_refined: bool = False