import re

class LLMRefiner:
    """
    Selective LLM-based template repair.
    """

    CORE_KEYS = {
        "DATASET",
        "NODE",
        "ACCESS",
        "ATTACK_TYPE",
        "POLICY",
        "MTD",
        "ATTACK_DETECTED",
        "THREAT_PROB",
        "RISK_SCORE",
        "VOLTAGE",
        "FREQUENCY",
        "POWER_FLOW",
        "REACTIVE_POWER",
        "COMM_SIZE",
        "UNCERTAINTY",
        "TEMPORAL_ENTROPY",
        "SPECTRAL_ENERGY",
        "SPATIAL_CORR",
        "SRC",
        "DST",
        "SPORT",
        "DPORT",
        "PROTO",
        "REQ_FUNC",
        "RESP_FUNC",
        "EVENT",
        "STATUS",
    }

    def __init__(self, backend):
        self.backend = backend

    def _template_similarity(self, a, b):
        a = list(a)
        b = list(b)

        if not a or not b:
            return 0.0

        max_len = max(len(a), len(b))
        matches = 0

        for x, y in zip(a, b):
            if str(x).strip() == str(y).strip():
                matches += 1

        return matches / max_len

    def _template_to_string(self, template):
        if isinstance(template, list):
            return " ".join(str(t) for t in template)

        return str(template)

    def _tokenize_template(self, template):
        return self._template_to_string(template).strip().split()

    def _extract_keys(self, template):
        keys = set()

        for token in self._tokenize_template(template):
            if "=" in token:
                key = token.split("=", 1)[0].strip().upper()
                keys.add(key)

        return keys

    def _canonicalize_llm_output(self, output, reference_template):
        output_tokens = self._tokenize_template(output)
        reference_tokens = self._tokenize_template(reference_template)

        output_map = {}

        for token in output_tokens:
            if "=" not in token:
                continue

            key, value = token.split("=", 1)
            key = key.strip().upper()
            value = value.strip()
            value_upper = value.upper()

            if value_upper in {"<IP>", "<NUMBER>", "<ID>", "<*>", "UNKNOWN"}:
                output_map[key] = value_upper
                continue

            if key == "DATASET":
                value = "<ID>"

            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
                value = "<IP>"

            elif re.fullmatch(r"-?\d+(\.\d+)?", value):
                if key in {"REQ_FUNC", "RESP_FUNC"}:
                    value = value
                else:
                    value = "<NUMBER>"

            elif key == "NODE":
                value = "<ID>"

            elif key in {"SRC", "DST"}:
                value = "<IP>"

            output_map[key] = value

        canonical = []

        for ref_token in reference_tokens:
            if "=" not in ref_token:
                continue

            ref_key, ref_value = ref_token.split("=", 1)
            ref_key_upper = ref_key.strip().upper()

            if ref_key_upper in output_map:
                canonical.append(f"{ref_key}={output_map[ref_key_upper]}")
            else:
                canonical.append(ref_token)

        return canonical

    def _has_broken_key_value_pattern(self, tokens):
        for token in tokens:
            if token in {"<*>", "UNKNOWN"}:
                continue

            if "=" not in token:
                return True

            key, value = token.split("=", 1)

            if key.strip() == "" or value.strip() == "":
                return True

        return False

    def _has_split_multivalue_field(self, tokens):
        semantic_prefixes = (
            "ATTACK_TYPE=",
            "POLICY=",
            "MTD=",
            "ACCESS=",
            "EVENT=",
            "STATUS=",
        )

        for i, token in enumerate(tokens):
            if not token.startswith(semantic_prefixes):
                continue

            j = i + 1

            while j < len(tokens):
                nxt = tokens[j]

                if "=" in nxt:
                    break

                if nxt not in {"<*>", "UNKNOWN"}:
                    return True

                j += 1

        return False

    def _has_many_orphan_tokens(self, tokens):
        key_value_count = sum(1 for token in tokens if "=" in token)
        orphan_count = sum(1 for token in tokens if "=" not in token)

        if key_value_count == 0:
            return False

        return orphan_count >= 2

    def _should_call_llm(self, candidate):
        tokens = self._tokenize_template(candidate.refined_template)

        if not tokens:
            return False

        if "<*>" in tokens:
            return True

        if any("UNKNOWN" in str(token) for token in tokens):
            return True

        if self._has_broken_key_value_pattern(tokens):
            return True

        if self._has_split_multivalue_field(tokens):
            return True

        if self._has_many_orphan_tokens(tokens):
            return True

        return False

    def _build_prompt(self, candidate):
        return f"""
You are a Smart Grid log template repair system.

Your task:
- repair malformed templates into valid format
- preserve Smart Grid semantic fields
- preserve key order where possible
- merge broken multi-word values using underscores
- remove orphan wildcard tokens if they are caused by broken splitting
- if a field is UNKNOWN or <*> and the original log contains the real value for the same key, restore it from the original log
- do not invent unrelated fields
- do not explain anything

Important:
- token count may change if needed for repair
- output one single template line only

Original log:
{candidate.raw_log}

Drain template:
{self._template_to_string(candidate.template)}

Context-refined template:
{self._template_to_string(candidate.refined_template)}

DCS:
{candidate.dcs["DCS"]}

CCS:
{candidate.ccs["CCS"]}

FCS:
{candidate.fcs}

Output rules:
- output exactly one line
- output only space-separated KEY=value tokens
- do not include sentences
- do not include comments
- do not say whether repair is needed
- do not explain
- IP addresses must be output as <IP>
- ports and protocol numbers must be output as <NUMBER>
- sensor and process values must be output as <NUMBER>
- DNP3 function codes may remain concrete values
- node/device identifiers must be output as <ID>

Output ONLY the repaired template.
""".strip()

    def _is_valid_repair(self, original_template, repaired_template):
        repaired_tokens = self._tokenize_template(repaired_template)

        if not repaired_tokens:
            return False

        repaired_text = self._template_to_string(repaired_template).lower()

        forbidden_phrases = [
            "this template",
            "no repair needed",
            "however",
            "i will",
            "instructions",
            "output only",
            "here is",
            "the repaired",
            "explanation",
            "template:",
            "output:",
        ]

        if any(phrase in repaired_text for phrase in forbidden_phrases):
            return False

        for token in repaired_tokens:
            if "=" not in token:
                return False

            key, value = token.split("=", 1)

            if key.strip() == "" or value.strip() == "":
                return False

        original_keys = self._extract_keys(original_template)
        repaired_keys = self._extract_keys(repaired_template)

        important_original_keys = original_keys.intersection(self.CORE_KEYS)
        missing_keys = important_original_keys - repaired_keys

        if missing_keys:
            return False

        return True

    def refine(self, candidate):
        should_call = self._should_call_llm(candidate)

        print("\n[LLM TRIGGER CHECK]")
        print("Should call LLM:", should_call)
        print("Template:", self._template_to_string(candidate.refined_template))

        if not should_call:
            candidate.llm_damage_detected = False
            candidate.llm_refined_template = candidate.refined_template.copy()
            candidate.llm_called = False
            candidate.llm_accepted = False
            candidate.llm_reason = "template_not_damaged"
            candidate.is_refined = False
            return candidate

        prompt = self._build_prompt(candidate)

        print("\n==============================")
        print("[LLM INPUT]")
        print("==============================")
        print(prompt)

        try:
            output = self.backend.generate(prompt)
            output = str(output).strip().replace("\n", " ")

            print("\n==============================")
            print("[LLM RAW OUTPUT]")
            print("==============================")
            print(output)

            canonical_output = self._canonicalize_llm_output(
                output,
                candidate.refined_template
            )

            print("\n==============================")
            print("[LLM CANONICAL OUTPUT]")
            print("==============================")
            print(" ".join(canonical_output))

            valid_format = self._is_valid_repair(
                candidate.refined_template,
                canonical_output
            )

            original_template = getattr(
                candidate,
                "original_refined_template",
                candidate.refined_template
            )

            damaged_score = self._template_similarity(
                candidate.refined_template,
                original_template
            )

            repaired_score = self._template_similarity(
                canonical_output,
                original_template
            )

            if valid_format and repaired_score >= damaged_score:
                candidate.llm_refined_template = canonical_output
                candidate.llm_called = True
                candidate.llm_accepted = True
                candidate.llm_reason = "valid_repair"
                candidate.is_refined = True

            else:
                candidate.llm_refined_template = candidate.refined_template.copy()
                candidate.llm_called = True
                candidate.llm_accepted = False
                candidate.llm_reason = "invalid_repair_fallback"
                candidate.is_refined = False

        except Exception as e:
            print("\n[LLM ERROR]")
            print(e)

            candidate.llm_refined_template = candidate.refined_template.copy()
            candidate.llm_called = True
            candidate.llm_accepted = False
            candidate.llm_reason = "llm_error_fallback"
            candidate.is_refined = False

        return candidate

