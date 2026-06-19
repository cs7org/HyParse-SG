import pandas as pd
from pathlib import Path


def _clean_eval_df(df):
    df.columns = [c.strip() for c in df.columns]

    # Remove fully empty rows and rows without template.
    df = df.dropna(how="all").copy()

    if "EventTemplate" in df.columns:
        df = df.dropna(subset=["EventTemplate"]).copy()
    elif "expected_template" in df.columns:
        df = df.dropna(subset=["expected_template"]).copy()

    return df.reset_index(drop=True)


def convert_reference_to_gt_eval(input_csv, output_csv):
    df = pd.read_csv(input_csv)
    df = _clean_eval_df(df)

    if "EventTemplate" in df.columns:
        template_col = "EventTemplate"
    elif "expected_template" in df.columns:
        template_col = "expected_template"
    else:
        raise ValueError(
            f"Could not find template column in {input_csv}. "
            f"Available columns: {list(df.columns)}"
        )

    if "EventId" in df.columns:
        event_id = df["EventId"].astype(str)
    elif "group_id" in df.columns:
        event_id = df["group_id"].astype(str)
    else:
        event_id = df[template_col].astype(str)

    out_df = pd.DataFrame({
        "LineId": range(1, len(df) + 1),
        "EventId": event_id,
        "EventTemplate": df[template_col].astype(str),
    })

    output_csv = Path(output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(output_csv, index=False)

    print(f"[DONE] Saved: {output_csv}")
    print(f"[ROWS] {len(out_df)}")
    print(f"[TEMPLATE COLUMN] {template_col}")


def make_gt_same_length_as_prediction(
    predicted_csv,
    ground_truth_csv,
    output_csv
):
    pred_df = pd.read_csv(predicted_csv)
    gt_df = pd.read_csv(ground_truth_csv)

    pred_df = _clean_eval_df(pred_df)
    gt_df = _clean_eval_df(gt_df)

    if "EventTemplate" not in gt_df.columns:
        raise ValueError(
            f"GT must contain EventTemplate. Available columns: {list(gt_df.columns)}"
        )

    n_pred = len(pred_df)

    if len(gt_df) < n_pred:
        raise ValueError(
            f"GT has fewer rows than prediction: gt={len(gt_df)}, pred={n_pred}"
        )

    matched_gt = gt_df.head(n_pred).copy()

    # Force LineId to match prediction exactly.
    if "LineId" in pred_df.columns:
        matched_gt["LineId"] = pred_df["LineId"].tolist()
    else:
        matched_gt["LineId"] = range(1, n_pred + 1)

    if "EventId" not in matched_gt.columns:
        matched_gt["EventId"] = matched_gt["EventTemplate"].astype(str)

    matched_gt = matched_gt[["LineId", "EventId", "EventTemplate"]]

    output_csv = Path(output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    matched_gt.to_csv(output_csv, index=False)

    print(f"[DONE] Saved matched GT: {output_csv}")
    print(f"[PREDICTED ROWS] {n_pred}")
    print(f"[MATCHED GT ROWS] {len(matched_gt)}")


if __name__ == "__main__":

    # Full GT files for Drain / Spell
    convert_reference_to_gt_eval(
        "Ground_Truth_Datasets/dnp3_balanced_ground_truth_eval.csv",
        "eval_ready/gt_dnp3.csv",
    )

    convert_reference_to_gt_eval(
        "Ground_Truth_Datasets/swat_ground_truth_eval.csv",
        "eval_ready/gt_swat.csv",
    )

    convert_reference_to_gt_eval(
        "Ground_Truth_Datasets/sg_security_ground_truth_eval.csv",
        "eval_ready/gt_sg_security.csv",
    )

    # Subset GT files
    convert_reference_to_gt_eval(
        "Ground_Truth_Datasets/dnp3_balanced_reference_100.csv",
        "eval_ready/gt_dnp3_100_raw.csv",
    )

    convert_reference_to_gt_eval(
        "Ground_Truth_Datasets/swat_reference_100.csv",
        "eval_ready/gt_swat_100_raw.csv",
    )

    convert_reference_to_gt_eval(
        "Ground_Truth_Datasets/sg_security_reference_100.csv",
        "eval_ready/gt_sg_security_100_raw.csv",
    )

    convert_reference_to_gt_eval(
        "Ground_Truth_Datasets/dnp3_balanced_reference_librelog.csv",
        "eval_ready/gt_dnp3_librelog_raw.csv",
    )

    convert_reference_to_gt_eval(
        "Ground_Truth_Datasets/swat_reference_librelog.csv",
        "eval_ready/gt_swat_librelog_raw.csv",
    )

    convert_reference_to_gt_eval(
        "Ground_Truth_Datasets/sg_security_reference_librelog.csv",
        "eval_ready/gt_sg_security_librelog_raw.csv",
    )

    # Matched GT files for LogPPT
    make_gt_same_length_as_prediction(
        "eval_ready/dnp3_logppt.csv",
        "eval_ready/gt_dnp3_100_raw.csv",
        "eval_ready/gt_dnp3_logppt_matched.csv",
    )

    make_gt_same_length_as_prediction(
        "eval_ready/swat_logppt.csv",
        "eval_ready/gt_swat_100_raw.csv",
        "eval_ready/gt_swat_logppt_matched.csv",
    )

    make_gt_same_length_as_prediction(
        "eval_ready/sg_security_logppt.csv",
        "eval_ready/gt_sg_security_100_raw.csv",
        "eval_ready/gt_sg_security_logppt_matched.csv",
    )

    # Matched GT files for LibreLog
    make_gt_same_length_as_prediction(
        "eval_ready/dnp3_librelog.csv",
        "eval_ready/gt_dnp3_librelog_raw.csv",
        "eval_ready/gt_dnp3_librelog_matched.csv",
    )

    make_gt_same_length_as_prediction(
        "eval_ready/swat_librelog.csv",
        "eval_ready/gt_swat_librelog_raw.csv",
        "eval_ready/gt_swat_librelog_matched.csv",
    )

    make_gt_same_length_as_prediction(
        "eval_ready/sg_security_librelog.csv",
        "eval_ready/gt_sg_security_librelog_raw.csv",
        "eval_ready/gt_sg_security_librelog_matched.csv",
    )