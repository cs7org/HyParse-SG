import pandas as pd
from baseline_tradeoff_metrics import BaselineTradeoffMetrics

EXPERIMENTS = [
    {
        "method_name": "HyParse-SG SWaT",
        "predicted_csv": "swat_predicted_eval.csv",
        "ground_truth_csv": "Ground_Truth_Datasets/swat_ground_truth_eval.csv",
        "total_time": 1.0,
    },

    {
         "method_name": "HyParse-SG SG_Security",
         "predicted_csv": "sg_security_predicted_eval.csv",
         "ground_truth_csv": "Ground_Truth_Datasets/sg_security_ground_truth_eval.csv",
         "total_time": 1.0,
    },

    {
        "method_name": "HyParse-SG DNP3",
        "predicted_csv": "dnp3_predicted_eval.csv",
        "ground_truth_csv": "Ground_Truth_Datasets/dnp3_balanced_ground_truth_eval.csv",
        "total_time": 1.0,
    },

]

def main():
    results = []

    for exp in EXPERIMENTS:
        result = BaselineTradeoffMetrics.evaluate_from_files(
            method_name=exp["method_name"],
            predicted_csv=exp["predicted_csv"],
            ground_truth_csv=exp["ground_truth_csv"],
            total_time=exp["total_time"],
            pred_template_col=exp.get("pred_template_col")
        )

        results.append(result)

        print("\n[EVALUATION RESULT]")
        for key, value in result.items():
            print(f"{key}: {value}")

    results_df = pd.DataFrame(results)
    results_df.to_csv(
        "rq4_results.csv",
        index=False
    )

    print("\n[DONE] Saved results")

if __name__ == "__main__":
    main()


