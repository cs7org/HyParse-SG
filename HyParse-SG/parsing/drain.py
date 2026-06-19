from parsing.tokens import TokenWeighter

class DrainNode:
    def __init__(self, depth=0):
        self.depth = depth
        self.children = {}
        self.clusters = []

class Template:
    def __init__(self, tokens, node):
        self.tokens = tokens
        self.node = node
        self.count = 1
        self.logs = [tokens.copy()]

    def update(self, new_tokens):
        """
            Update template with new log tokens.
            """
        protected_prefixes = (
            "EVENT=",
            "REQ_FUNC=",
            "RESP_FUNC=",
            "LINK_FUNC="
        )

        for i in range(len(self.tokens)):

            current = self.tokens[i]
            new = new_tokens[i]

            if current.startswith(protected_prefixes):
                continue

            if new.startswith(protected_prefixes):
                continue

            if current != new:
                self.tokens[i] = "<*>"

        self.logs.append(new_tokens.copy())
        self.count += 1

class DrainParser:

    def __init__(self, classifier, max_depth=5, sim_threshold=0.6):
        self.root = DrainNode()
        self.max_depth = max_depth
        self.sim_threshold = sim_threshold
        self.classifier = classifier
        self.weighter = TokenWeighter()
        self.clusters = []

    def _similarity(self, t1, t2):
        semantic_prefixes = (
            "EVENT=",
            "REQ_FUNC=",
            "RESP_FUNC=",
            "LINK_FUNC="
        )

        for t1, t2 in zip(t1, t2):
            if t1.startswith(semantic_prefixes):
                if t1 != t2:
                    return 0.0

        num = denom = 0
        for a, b in zip(t1, t2):
            w = self.weighter.get_weight(self.classifier.classify(a))
            denom += w
            if a == b or a == "<*>" or b == "<*>":
                num += w
        return num / denom if denom else 0

    def _tree_search(self, tokens):
        node = self.root
        for i in range(min(self.max_depth, len(tokens))):
            tok = tokens[i]
            if tok in node.children:
                node = node.children[tok]
            elif "<*>" in node.children:
                node = node.children["<*>"]
            else:
                break
        return node

    def _add_to_tree(self, tokens):
        node = self.root
        for i in range(min(self.max_depth, len(tokens))):
            tok = tokens[i]
            if tok not in node.children:
                node.children[tok] = DrainNode(i + 1)
            node = node.children[tok]
        return node

    def parse(self, log):
        tokens = log.tokens
        node = self._tree_search(tokens)

        best = None
        best_sim = -1

        for c in node.clusters:
            sim = self._similarity(tokens, c.tokens)
            if sim > best_sim:
                best_sim = sim
                best = c

        if best and best_sim >= self.sim_threshold:
            best.update(tokens)
            return best

        leaf = self._add_to_tree(tokens)
        new = Template(tokens.copy(), leaf)
        leaf.clusters.append(new)
        self.clusters.append(new)
        return new