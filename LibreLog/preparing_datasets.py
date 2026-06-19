import re
import pandas as pd
from pathlib import Path


# ============================================================
# INPUT / OUTPUT CONFIG
# ============================================================

DATASETS = {
    "SG_SECURITY": {
        "input": Path("full_dataset/security_dataset.csv"),
        "output_dir": Path("full_dataset/SG_SECURITY"),
        "output_file": "SG_SECURITY_full.log_structured.csv",
        "dataset_token": "SG_SECURITY",
    },

    "SWAT_ATTACK": {
        "input": Path("full_dataset/swat_attack.csv"),
        "output_dir": Path("full_dataset/SWAT_ATTACK"),
        "output_file": "SWAT_ATTACK_full.log_structured.csv",
        "dataset_token": "SWAT",
    },

    "DNP3_BALANCED": {
        "input": Path("full_dataset/dnp3_balanced.csv"),
        "output_dir": Path("full_dataset/DNP3_BALANCED"),
        "output_file": "DNP3_BALANCED_full.log_structured.csv",
        "dataset_token": "DNP3",
    },
}


# ============================================================
# HELPERS
# ============================================================

def normalize_key(col):
    key = str(col).strip().upper()

    key = key.replace("/", "_S")
    key = key.replace("-", "_")
    key = key.replace(" ", "_")
    key = key.replace(".", "_")
    key = key.replace(":", "_")
    key = key.replace("(", "")
    key = key.replace(")", "")

    key = re.sub(r"[^A-Z0-9_]", "_", key)
    key = re.sub(r"_+", "_", key)

    return key.strip("_")


def safe_value(value):
    if pd.isna(value):
        return "UNKNOWN"

    value = str(value).strip()

    if value == "":
        return "UNKNOWN"

    value = value.replace(" ", "_")
    value = value.replace("\t", "_")
    value = value.replace("\n", "_")
    value = value.replace("\r", "_")

    return value


def row_to_content(row, dataset_token):
    fields = [
        f"DATASET={dataset_token}"
    ]

    for col in row.index:
        key = normalize_key(col)

        # Avoid duplicate dataset field if present
        if key in {"DATASET"}:
            continue

        value = safe_value(row[col])
        fields.append(f"{key}={value}")

    return " ".join(fields)


def convert_dataset(name, cfg):
    input_path = cfg["input"]
    output_dir = cfg["output_dir"]
    output_path = output_dir / cfg["output_file"]
    dataset_token = cfg["dataset_token"]

    if not input_path.exists():
        print(f"[SKIPPED] {name}: input not found: {input_path}")
        return

    df = pd.read_csv(input_path)
    df.columns = [str(c).strip() for c in df.columns]

    rows = []

    for idx, row in df.iterrows():
        content = row_to_content(
            row,
            dataset_token=dataset_token
        )

        rows.append({
            "LineId": idx + 1,
            "Content": content
        })

    output_dir.mkdir(parents=True, exist_ok=True)

    pd.DataFrame(rows).to_csv(
        output_path,
        index=False
    )

    print(f"[DONE] {name}: saved {output_path}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    for name, cfg in DATASETS.items():
        convert_dataset(name, cfg)