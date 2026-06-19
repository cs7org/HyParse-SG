class DrainConfidenceScorer:

    def __init__(self, classifier, weighter, max_depth=10, beta=0.5, epsilon=1e-6):
        self.classifier = classifier
        self.weighter = weighter
        self.max_depth = max_depth
        self.beta = beta
        self.epsilon = epsilon

    def weighted_token_match_ratio(self, log_tokens, template_tokens):
        num = denom = 0
        for l, t in zip(log_tokens, template_tokens):
            w = self.weighter.get_weight(self.classifier.classify(l))
            denom += w
            if l == t or t == "<*>":
                num += w
        return num / denom if denom else 0

    def template_depth(self, template, max_cluster_size):
        """
        Computes template structural confidence.
        """
        token_count = len(template.tokens)

        if token_count == 0:
            return 0.0

        depth_norm = min(
            template.node.depth / self.max_depth,
            1.0
        )

        depth_score = 0.8 * depth_norm

        wildcard_count = template.tokens.count("<*>")

        specificity = 1 - (
                wildcard_count / token_count
        )

        score = (
                0.5 * depth_score
                + 0.5 * specificity
        )

        return min(score, 1.0)

    def cluster_integrity(self, template):
        logs = template.logs

        if len(logs) <= 1:
            return 1.0

        protected_prefixes = (
            "EVENT=",
            "REQ_FUNC=",
            "RESP_FUNC="
        )

        semantic_changes = 0
        structural_changes = 0
        checked_positions = 0

        for i in range(len(template.tokens)):
            values = []

            for log in logs:
                if i < len(log):
                    values.append(log[i])

            if not values:
                continue

            checked_positions += 1

            unique_values = set(values)

            if len(unique_values) <= 1:
                continue

            if any(
                    str(v).startswith(protected_prefixes)
                    for v in unique_values
            ):
                semantic_changes += 1
            else:
                structural_changes += 1

        penalty = (
                1.0 * semantic_changes
                + 0.5 * structural_changes
        )

        return max(
            0.0,
            1 - (penalty / checked_positions)
        )

    def separation_assurance(self, template):
        """
            Estimates whether separators and field structures are stable
            inside a template cluster.
            """
        logs = template.logs

        if not logs:
            return 0.0

        if len(logs) == 1:
            return 1.0

        template_len = len(template.tokens)

        total_tokens = 0
        separator_tokens = 0

        for log in logs:
            for token in log:
                total_tokens += 1
                if "=" in token:
                    separator_tokens += 1

        separator_presence = (
            separator_tokens / total_tokens
            if total_tokens else 0.0
        )

        consistent_positions = 0

        for pos in range(template_len):
            values_at_pos = []

            for log in logs:
                if pos < len(log):
                    token = log[pos]

                    if "=" in token:
                        field_name = token.split("=", 1)[0]
                        values_at_pos.append(field_name)
                    else:
                        values_at_pos.append(token)

            if values_at_pos:
                most_common_count = max(
                    values_at_pos.count(v)
                    for v in set(values_at_pos)
                )

                consistency = most_common_count / len(values_at_pos)

                if consistency >= 0.9:
                    consistent_positions += 1

        position_consistency = (
            consistent_positions / template_len
            if template_len else 0.0
        )

        reference_fields = []

        for token in logs[0]:
            if "=" in token:
                reference_fields.append(
                    token.split("=", 1)[0]
                )
            else:
                reference_fields.append(token)

        matching_logs = 0

        for log in logs:
            fields = []

            for token in log:
                if "=" in token:
                    fields.append(
                        token.split("=", 1)[0]
                    )
                else:
                    fields.append(token)

            if fields == reference_fields:
                matching_logs += 1

        field_structure_consistency = (
            matching_logs / len(logs)
            if logs else 0.0
        )

        separation_assurance = (
                0.3 * separator_presence
                + 0.3 * position_consistency
                + 0.4 * field_structure_consistency
        )

        return separation_assurance

    def protocol_consistency(self, tokens):
            """
            SG-aware protocol consistency.
            """
            token_text = " ".join(tokens)

            dnp3_expected = [
                "SRC=",
                "DST=",
                "SPORT=",
                "DPORT=",
                "PROTO=",
                "DNP3_SRC=",
                "DNP3_DST=",
                "LINK_FUNC=",
                "REQ_FUNC=",
                "RESP_FUNC=",
                "EVENT="
            ]

            swat_expected_prefixes = [
                "FIT",
                "LIT",
                "AIT",
                "P",
                "MV"
            ]

            dnp3_matches = sum(
                1 for field in dnp3_expected
                if field in token_text
            )

            if dnp3_matches >= 4:
                return dnp3_matches / len(dnp3_expected)

            swat_matches = sum(
                1 for token in tokens
                if token.startswith(tuple(swat_expected_prefixes))
            )

            if swat_matches > 0:
                return min(swat_matches / 5, 1.0)

            return 0.0

    def compute(self, log_tokens, template, clusters):
        max_cluster_size = max(c.count for c in clusters)
        wtmr = self.weighted_token_match_ratio(log_tokens, template.tokens)
        td = self.template_depth(template, max_cluster_size)
        ci = self.cluster_integrity(template)
        sa = self.separation_assurance(template)
        pc = self.protocol_consistency(log_tokens)

        dcs = (0.25 * wtmr + 0.15 * td + 0.20 * ci + 0.15 * sa + 0.25 * pc)

        return {
            "DCS": dcs,
            "WTMR": wtmr,
            "TemplateDepth": td,
            "ClusterIntegrity": ci,
            "SeparationAssurance": sa,
            "ProtocolConsistency": pc
        }
