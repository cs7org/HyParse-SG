class PromptBuilder:

    @staticmethod
    def build_refinement_prompt(candidate):

        return f"""
You are a Smart Grid log template repair system.

Your task:
- repair malformed templates into valid format
- preserve Smart Grid semantic fields
- preserve key order where possible
- merge broken multi-word values using underscores
- remove orphan wildcard tokens if they are caused by broken splitting
- do not invent unrelated fields
- do not explain anything

Important:
- token count may change if needed for repair
- output one single template line only

Original Log:
{candidate.raw_log}

Drain Template:
{' '.join(candidate.template)}

Context-Refined Template:
{' '.join(candidate.refined_template)}

DCS:
{candidate.dcs["DCS"]:.4f}

CCS:
{candidate.ccs["CCS"]:.4f}

FCS:
{candidate.fcs:.4f}

Output ONLY the repaired template.
""".strip()