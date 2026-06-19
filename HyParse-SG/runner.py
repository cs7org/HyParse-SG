"""
Main execution pipeline for the Hybrid Smart Grid Log Parser.
Pipeline:
-Dataset Loader
-SG Preprocessing
-Drain Parsing
-Contextual Parsing
-DCS / CCS / FCS
-Template Buffer
-Decision Engine
-LLM Refinement
-Evaluation
"""
import copy
import time
import random
import numpy as np

from config import Config
from llm.refiner import LLMRefiner
from llm.template_damage import TemplateDamager


# DATASETS

from dataset.factory import DatasetFactory


# PREPROCESSING


from preprocessing.preprocessor import SGPreprocessor
from preprocessing.buffer import NormalizedLogBuffer


# PARSING


from parsing.tokens import TokenClassifier, TokenWeighter
from parsing.drain import DrainParser


# CONTEXTUAL PARSER


from contextual.context_parser import ContextualParser


# SCORING


from scoring.dcs import DrainConfidenceScorer
from scoring.ccs import CCSScorer, DeviceTransitionTracker
from scoring.fcs import FCSCombiner


# PIPELINE


from pipeline.template_buffer import TemplateBuffer
from pipeline.candidate import TemplateCandidate
from pipeline.decision import DecisionEngine


# LLM


from llm.ollama_backend import OllamaBackend


# EVALUATION


from evaluation.dataset import EvaluationDataset
from evaluation.evaluator import Evaluator


# RESULTS


from results.results_writer import ResultsWriter


class HybridLogParserSystem:
    """
    Main Hybrid Smart Grid Log Parsing System.
    """

    def __init__(
        self,
        dataset_type,
        dataset_path,
        limit=None
    ):

        self.dataset_type = dataset_type


        # DATASET LOADER


        self.loader = DatasetFactory.create(
            dataset_type,
            dataset_path,
            limit=limit
        )


        # PREPROCESSING


        self.preprocessor = SGPreprocessor()

        self.normalized_buffer = (
            NormalizedLogBuffer()
        )


        # PARSING


        self.classifier = TokenClassifier()

        self.weighter = TokenWeighter()

        self.drain = DrainParser(
            classifier=self.classifier,
            max_depth=Config.MAX_DEPTH,
            sim_threshold=Config.SIM_THRESHOLD
        )


        # CONTEXTUAL PARSER


        self.contextual = ContextualParser(
            classifier=self.classifier,
            n=Config.NGRAM_N
        )

        # SCORING


        self.dcs_scorer = (
            DrainConfidenceScorer(
                classifier=self.classifier,
                weighter=self.weighter,
                max_depth=Config.MAX_DEPTH
            )
        )

        self.transition_tracker = (
            DeviceTransitionTracker()
        )

        self.ccs_scorer = CCSScorer(
            model=self.contextual.model,
            tracker=self.transition_tracker,
            gamma=Config.GAMMA
        )

        self.fcs_combiner = FCSCombiner(
            alpha=Config.ALPHA
        )


        # TEMPLATE BUFFER


        self.template_buffer = TemplateBuffer()


        # RAW DATASET STORAGE


        self.loaded_logs = []


        # RESULTS WRITER


        self.results_writer = ResultsWriter()


    # INGEST + PREPROCESS LOGS


    def ingest_logs(self):
        """
        Load logs from dataset and preprocess them.
        """
        logs = self.loader.load()

        self.loaded_logs = logs

        for log in logs:

            log.tokens = []

            processed = self.preprocessor.preprocess(log)

            self.normalized_buffer.push(processed)

            print("\n[PREPROCESSED]")
            print(log.tokens)


    # MAIN PARSING + SCORING PIPELINE

    def process_logs(self):

        pipeline_start = time.time()

        before_llm = []

        while not self.normalized_buffer.is_empty():

            log_start = time.time()

            log = self.normalized_buffer.pop()

            # DRAIN PARSING


            template = self.drain.parse(log)

            print("\n[DRAIN TEMPLATE]")
            print(template.tokens)


            # CONTEXTUAL PARSING

            if Config.USE_CONTEXTUAL:

                context_result = self.contextual.process(log, template)

            else:

                context_result = {
                    "refined_template": template.tokens.copy(),
                    "device": "CONTEXT_DISABLED"
                }

                print("\n[CONTEXT]")
                print(context_result)


            # DCS


            dcs_result = (
                self.dcs_scorer.compute(
                    log.tokens,
                    template,
                    self.drain.clusters
                )
            )

            print("\n[DCS]")
            print(dcs_result)


            # CCS


            if Config.USE_CONTEXTUAL:

                ccs_result = self.ccs_scorer.compute(
                    context_result["device"],
                    self.contextual.history,
                    tuple(context_result["refined_template"])
                )

            else:

                ccs_result = {
                    "CCS": 0,
                    "DANF": 0,
                    "DTC": 0
                }

            print("\n[CCS]")
            print(ccs_result)


            # FINAL CONFIDENCE SCORE


            fcs = self.fcs_combiner.compute(
                dcs_result["DCS"],
                ccs_result["CCS"]
            )

            print("\n[FCS]")
            print(fcs)

            if Config.USE_CONTEXTUAL:
                self.contextual.update_model(
                    context_result["device"],
                    context_result["refined_template"]
                )

            # TEMPLATE CANDIDATE

            candidate = TemplateCandidate(
                log_id=log.log_id,

                raw_log=log.raw_text,

                template=template.tokens.copy(),

                refined_template=context_result[
                    "refined_template"
                ].copy(),

                device=context_result.get(
                    "device",
                    "CONTEXT_DISABLED"
                ),

                dcs=dcs_result,

                ccs=ccs_result,

                fcs=fcs
            )

            candidate.dataset = self.dataset_type

            candidate.normalized_tokens = (
                log.tokens.copy()
            )

            candidate.is_anomaly = (
                getattr(
                    log,
                    "is_anomaly",
                    False
                )
            )

            if Config.USE_CONTEXTUAL:
                danf = ccs_result.get("DANF", 0)
                dtc = ccs_result.get("DTC", 1)

                refined_template = context_result.get(
                    "refined_template",
                    []
                )

                event_value = "UNKNOWN"

                for token in refined_template:
                    if str(token).startswith("EVENT="):
                        event_value = str(token).split("=", 1)[1].upper()
                        break

                dataset_name = str(candidate.dataset).upper()
                raw_text = str(log.raw_text).upper()
                refined_text = " ".join(str(t).upper() for t in refined_template)

                suspicious_events = {
                    "ARP_POISONING",
                    "MITM",
                    "DOS",
                    "REPLAY",
                    "COLD_RESTART",
                    "WARM_RESTART",
                    "STOP_APP",
                    "DISABLE_UNSOLICITED",
                    "ENABLE_UNSOLICITED",
                    "INIT_DATA",
                    "DNP3_INFO",
                    "INFO",
                    "DNP3_ENUMERATE",
                }

                benign_events = {
                    "NORMAL",
                    "BENIGN",
                }

                semantic_anomaly = (
                        event_value in suspicious_events
                )

                contextual_anomaly = (
                        danf == 1
                        and (
                                fcs < Config.FCS_THRESHOLD
                                or dtc == 0
                        )
                )

                if "DNP3" in dataset_name:

                    candidate.predicted_anomaly = (
                            (
                                    semantic_anomaly
                                    and event_value not in {
                                        "INIT_DATA",
                                        "DISABLE_UNSOLICITED",
                                        "ENABLE_UNSOLICITED",
                                    }
                            )
                            or (
                                    semantic_anomaly
                                    and event_value in {
                                        "INIT_DATA",
                                        "DISABLE_UNSOLICITED",
                                        "ENABLE_UNSOLICITED",
                                    }
                                    and (
                                            danf == 1
                                            or dtc == 0
                                            or fcs < Config.FCS_THRESHOLD
                                    )
                            )
                            or (
                                    danf == 1
                                    and (
                                            dtc == 0
                                            or fcs < Config.FCS_THRESHOLD
                                    )
                            )
                    )


                elif "SWAT" in dataset_name:

                    status_value = "UNKNOWN"

                    for token in refined_template:
                        if str(token).startswith("STATUS="):
                            status_value = str(token).split("=", 1)[1].upper()
                            break

                    candidate.predicted_anomaly = (
                            status_value == "ATTACK"
                            and (
                                    danf == 1
                                    or dtc == 0
                                    or fcs < Config.FCS_THRESHOLD
                            )
                    )


                elif "SG" in dataset_name or "SECURITY" in dataset_name:

                    attack_type_detected = (

                            "ATTACK_TYPE=DOS" in raw_text

                            or "ATTACK_TYPE=MITM" in raw_text

                            or "ATTACK_TYPE=ZERO-DAY" in raw_text

                            or "ATTACK_TYPE=FALSE_DATA_INJECTION" in raw_text

                            or "ATTACK_TYPE=FALSE-DATA-INJECTION" in raw_text

                            or "ATTACK_TYPE=DATA_INJECTION" in raw_text

                    )

                    high_risk_policy = (

                            "POLICY=ISOLATE_NODE" in raw_text

                            or "POLICY=RESTRICT_ACCESS" in raw_text

                    )

                    suspicious_access = (

                            "ACCESS=COMMAND_EXEC" in raw_text

                            or "ACCESS=FILE_ACCESS" in raw_text

                    )

                    candidate.predicted_anomaly = (
                            attack_type_detected
                            or (
                                    high_risk_policy
                                    and suspicious_access
                            )
                            or contextual_anomaly
                    )


                else:

                    candidate.predicted_anomaly = contextual_anomaly


            candidate.parsing_time = (
                time.time() - log_start
            )

            candidate.original_refined_template = (
                candidate.refined_template.copy()
            )

            candidate.template_damaged = False

            if Config.LLM_STRESS_TEST:
                damaged_template, was_damaged = TemplateDamager.damage(
                    candidate.refined_template,
                    dataset_name=self.dataset_type,
                    rate=Config.LLM_DAMAGE_RATE
                )

                candidate.refined_template = damaged_template
                candidate.template_damaged = was_damaged

                print("\n[DAMAGE DEBUG]")
                print("Damaged:", was_damaged)
                print("Original:", candidate.original_refined_template)
                print("Current:", candidate.refined_template)

            # STORE


            self.template_buffer.push(candidate)

            before_llm.append(
                copy.deepcopy(candidate)
            )

        total_time = (
            time.time() - pipeline_start
        )

        return before_llm, total_time


    # LLM REFINEMENT STAGE


    def refine_templates(
        self,
        refiner
    ):

        decision_engine = DecisionEngine(
            threshold=Config.FCS_THRESHOLD,
            refiner=refiner
        )

        final_results = (
            decision_engine.process(
                self.template_buffer
            )
        )

        return final_results

    # SAVE RESULTS


    def save_results(
        self,
        before_llm,
        after_llm,
        total_time,
        model_name,
        metrics=None
    ):

        self.results_writer.write_csv(
            before_llm=before_llm,
            after_llm=after_llm,
            total_time=total_time,
            model_name=model_name,
            dataset_name=self.dataset_type,
            metrics=metrics
        )


    # EVALUATION


    def evaluate(
            self,
            before_llm,
            after_llm,
            total_time
    ):

        dataset = EvaluationDataset(self.loaded_logs)

        evaluator = Evaluator(dataset)

        timing = {
            "total_time": total_time,
            "cost_llm_all": len(before_llm),
            "cost_hybrid": sum(
                1 for x in after_llm
                if getattr(x, "llm_called", False)
            )
        }

        results = evaluator.evaluate_all(
            before_llm,
            after_llm,
            timing
        )

        return results


# MAIN EXECUTION


if __name__ == "__main__":

    random.seed(42)
    np.random.seed(42)

    system = HybridLogParserSystem(

        dataset_type="dnp3",
        #dataset_path="data/SG-Security_Dataset/security_dataset.csv",
        #dataset_path="data/SWaT_Dataset/attack.csv",
        #dataset_path="data/DNP3_Dataset/Training_Testing_Balanced_CSV_Files/Custom_DNP3_Parser/Custom_DNP3_Parser_Testing_Balanced.csv",
        limit=1000
    )


    # LOAD + PREPROCESS

    print("\nLoading dataset...")

    system.ingest_logs()

    # PARSING + SCORING


    print("Running parsing pipeline...")

    before_llm, total_time = (
        system.process_logs()
    )

    print(
        f"Processed {len(before_llm)} logs"
    )

    # TEST MULTIPLE LLMs


    for model_name in Config.LLM_MODELS:

        print(f"\n==============================")
        print(f"Testing model: {model_name}")
        print(f"==============================")

        # RESTORE TEMPLATE BUFFER


        system.template_buffer.buffer.clear()

        for candidate in copy.deepcopy(
            before_llm
        ):

            system.template_buffer.push(
                candidate
            )

        # CREATE BACKEND


        backend = OllamaBackend(
            model_name
        )

        refiner = LLMRefiner(
            backend
        )

        # RUN LLM REFINEMENT


        after_llm = (
            system.refine_templates(
                refiner
            )
        )

        print(
            f"Finished refinement "
            f"with {model_name}"
        )


        # SAVE RESULTS TO CSV


        system.save_results(
            before_llm=before_llm,
            after_llm=after_llm,
            total_time=total_time,
            model_name=model_name
        )

        metrics = system.evaluate(
            before_llm=before_llm,
            after_llm=after_llm,
            total_time=total_time
        )

        print("\n[EVALUATION METRICS]")
        for metric_name, metric_value in metrics.items():
            print(f"{metric_name}: {metric_value}")

        system.save_results(
            before_llm=before_llm,
            after_llm=after_llm,
            total_time=total_time,
            model_name=model_name,
            metrics=metrics
        )

    print("Pipeline execution completed.")






