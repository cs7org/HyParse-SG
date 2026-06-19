from evaluation.metrics import Metrics
from config import Config

class Evaluator:

    def __init__(self, dataset):
        self.dataset = dataset

    # STRUCTURAL EVALUATION

    #def evaluate_structural(self, results):
        #correct_pa = 0
        #total = len(results)

        #predicted_groups = {}

        #for r in results:
            #gt_template = self.dataset.get_template(r.log_id)
            #predicted_template = " ".join(r.refined_template)

            #if gt_template is not None:
                #gt_sig = self._normalize_sg_template(gt_template)
                #pred_sig = self._normalize_sg_template(predicted_template)

                #if gt_sig and pred_sig and gt_sig == pred_sig:
                    #correct_pa += 1

            #key = tuple(r.refined_template)

            #predicted_groups.setdefault(
                #key,
                #[]
            #).append(r.log_id)

        #correct_ga = 0

        #for group in predicted_groups.values():
            #gt_groups = [
                #self.dataset.get_group(i)
                #for i in group
            #]

            #if len(set(gt_groups)) == 1:
                #correct_ga += len(group)

        #return {
            #"PA": Metrics.parsing_accuracy(
                #correct_pa,
                #total
            #),
            #"GA": Metrics.grouping_accuracy(
                #correct_ga,
                #total
            #)
        #}

    # CONTEXTUAL EVALUATION

    def evaluate_contextual(self, results):

        TP = FP = FN = 0

        for r in results:

            gt = getattr(
                r,
                "is_anomaly",
                self.dataset.is_anomaly(r.log_id)
            )

            pred = getattr(
                r,
                "predicted_anomaly",
                False
            )

            if pred and gt:
                TP += 1

            elif pred and not gt:
                FP += 1

            elif not pred and gt:
                FN += 1

        p = Metrics.precision(TP, FP)
        r = Metrics.recall(TP, FN)
        f1 = Metrics.f1(p, r)

        return {
            "Precision": p,
            "Recall": r,
            "F1": f1,
            "TP": TP,
            "FP": FP,
            "FN": FN
        }

    # LLM EVALUATION

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

    def evaluate_llm(self, before, after):
        improved = 0
        degraded = 0
        correctly_repaired = 0
        total_llm = 0

        for b, a in zip(before, after):

            if not getattr(b, "template_damaged", False):
                continue

            if not getattr(a, "llm_called", False):
                continue

            original = getattr(b, "original_refined_template", None)
            damaged = getattr(b, "refined_template", None)
            repaired = getattr(a, "llm_refined_template", None)

            if original is None or damaged is None or repaired is None:
                continue

            original = list(original)
            damaged = list(damaged)
            repaired = list(repaired)

            total_llm += 1

            damaged_score = self._template_similarity(
                damaged,
                original
            )

            repaired_score = self._template_similarity(
                repaired,
                original
            )

            if repaired_score == 1.0:
                correctly_repaired += 1
                improved += 1

            elif repaired_score > damaged_score:
                improved += 1

            elif repaired_score < damaged_score:
                degraded += 1

        total_logs = len(before)

        return {
            "CPR": Metrics.correction_precision_rate(
                improved,
                total_llm
            ),
            "CDR": Metrics.correction_degradation_rate(
                degraded,
                total_llm
            ),
            "CC": Metrics.correction_coverage(
                correctly_repaired,
                total_logs
            )
        }

    # EFFICIENCY EVALUATION

    def evaluate_efficiency(self, timing, total_logs):

        PT = Metrics.throughput(total_logs, timing["total_time"])
        MLL = Metrics.mean_latency(timing["total_time"], total_logs)
        LLM_CR = Metrics.llm_cost_reduction(
            timing["cost_llm_all"],
            timing["cost_hybrid"]
        )

        return {
            "PT": PT,
            "MLL": MLL,
            "LLM_CR": LLM_CR
        }

    # FULL EVALUATION

    def evaluate_all(self, before_llm, after_llm, timing):

        results = {}

        #results.update(self.evaluate_structural(after_llm))
        results.update(self.evaluate_contextual(after_llm))
        results.update(self.evaluate_llm(before_llm, after_llm))
        results.update(self.evaluate_efficiency(timing, len(after_llm)))

        return results