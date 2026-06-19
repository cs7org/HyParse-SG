from evaluation.baseline_tradeoff_metrics import BaselineTradeoffMetrics

experiments = [
    {
        "method": "Drain DNP3",
        "predicted": "eval_ready/dnp3_drain.csv",
        "ground_truth": "eval_ready/gt_dnp3.csv",
        "time": 1.0,
    },
    {
        "method": "Spell DNP3",
        "predicted": "eval_ready/dnp3_spell.csv",
        "ground_truth": "eval_ready/gt_dnp3.csv",
        "time": 1.0,
    },
    {
        "method": "LibreLog DNP3",
        "predicted": "eval_ready/dnp3_librelog.csv",
        "ground_truth": "eval_ready/gt_dnp3_librelog_matched.csv",
        "time": 1.0,
    },
    {
        "method": "LogPPT DNP3",
        "predicted": "eval_ready/dnp3_logppt.csv",
        "ground_truth": "eval_ready/gt_dnp3_logppt_matched.csv",
        "time": 1.0,
    },
    {
        "method": "Drain SG-Security",
        "predicted": "eval_ready/sg_security_drain.csv",
        "ground_truth": "eval_ready/gt_sg_security.csv",
        "time": 1.0,
    },
    {
        "method": "Spell SG-Security",
        "predicted": "eval_ready/sg_security_spell.csv",
        "ground_truth": "eval_ready/gt_sg_security.csv",
        "time": 1.0,
    },
    {
        "method": "LibreLog SG-Security",
        "predicted": "eval_ready/sg_security_librelog.csv",
        "ground_truth": "eval_ready/gt_sg_security_librelog_matched.csv",
        "time": 1.0,
    },
    {
        "method": "LogPPT SG-Security",
        "predicted": "eval_ready/sg_security_logppt.csv",
        "ground_truth": "eval_ready/gt_sg_security_logppt_matched.csv",
        "time": 1.0,
    },
    {
        "method": "Drain SWaT",
        "predicted": "eval_ready/swat_drain.csv",
        "ground_truth": "eval_ready/gt_swat.csv",
        "time": 1.0,
    },
    {
        "method": "Spell SWaT",
        "predicted": "eval_ready/swat_spell.csv",
        "ground_truth": "eval_ready/gt_swat.csv",
        "time": 1.0,
    },
    {
        "method": "LibreLog SWaT",
        "predicted": "eval_ready/swat_librelog.csv",
        "ground_truth": "eval_ready/gt_swat_librelog_matched.csv",
        "time": 1.0,
    },
    {
        "method": "LogPPT SWaT",
        "predicted": "eval_ready/swat_logppt.csv",
        "ground_truth": "eval_ready/gt_swat_logppt_matched.csv",
        "time": 1.0,
    },
]

results = []

for exp in experiments:
    result = BaselineTradeoffMetrics.evaluate_from_files(
        method_name=exp["method"],
        predicted_csv=exp["predicted"],
        ground_truth_csv=exp["ground_truth"],
        total_time=exp["time"],
    )

    results.append(result)

for r in results:
    print(r)