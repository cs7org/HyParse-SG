class Metrics:

    # STRUCTURAL METRICS

    @staticmethod
    def parsing_accuracy(correct, total):
        return correct / total if total else 0

    @staticmethod
    def grouping_accuracy(correct, total):
        return correct / total if total else 0

    # CONTEXTUAL METRICS

    @staticmethod
    def precision(tp, fp):
        return tp / (tp + fp) if (tp + fp) else 0

    @staticmethod
    def recall(tp, fn):
        return tp / (tp + fn) if (tp + fn) else 0

    @staticmethod
    def f1(p, r):
        return (2 * p * r) / (p + r) if (p + r) else 0

    # LLM METRICS

    @staticmethod
    def correction_precision_rate(improved, total_llm):
        return improved / total_llm if total_llm else 0

    @staticmethod
    def correction_degradation_rate(degraded, total_llm):
        return degraded / total_llm if total_llm else 0

    @staticmethod
    def correction_coverage(correctly_repaired, total_logs):
        return correctly_repaired / total_logs if total_logs else 0

    # EFFICIENCY METRICS

    @staticmethod
    def throughput(total_logs, total_time):
        return total_logs / total_time if total_time > 0 else 0

    @staticmethod
    def mean_latency(total_time, total_logs):
        return total_time / total_logs if total_logs > 0 else 0

    @staticmethod
    def llm_cost_reduction(cost_llm_all, cost_hybrid):
        return 1 - (cost_hybrid / cost_llm_all) if cost_llm_all > 0 else 0