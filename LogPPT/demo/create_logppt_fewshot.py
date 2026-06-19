import json
import re
import pandas as pd
from pathlib import Path


PROJECT_ROOT = Path(
    r"C:\Users\PC\Desktop\Master_Thesis\HyParse-SG_Implementation\LogPPT\LogPPT-master"
)

#DATASET = "SG_SECURITY"
#DATASET = "SWAT_ATTACK"
DATASET = "DNP3_BALANCED"

DATASET_CONFIG = {
    "SG_SECURITY": {
        "raw_gt": PROJECT_ROOT / "sg_security_reference.csv",
        "out_dir": PROJECT_ROOT / "sg_datasets" / "SG_SECURITY",
    },
    "SWAT_ATTACK": {
        "raw_gt": PROJECT_ROOT / "swat_reference.csv",
        "out_dir": PROJECT_ROOT / "sg_datasets" / "SWAT_ATTACK",
    },
    "DNP3_BALANCED": {
        "raw_gt": PROJECT_ROOT / "dnp3_balanced_reference.csv",
        "out_dir": PROJECT_ROOT / "sg_datasets" / "DNP3_BALANCED",
    },
}

TRAIN_SIZE = 32
VALIDATION_SIZE = 50
RANDOM_SEED = 42


def safe(value):
    if pd.isna(value):
        return "UNKNOWN"

    return str(value).strip().replace(" ", "_")


def get(row, candidates, default="UNKNOWN"):
    for col in candidates:
        if col in row.index:
            return safe(row[col])

    return default


def number_template(key):
    return f"{key}=<NUMBER>"


def id_template(key):
    return f"{key}=<ID>"


def ip_template(key):
    return f"{key}=<IP>"


# ============================================================
# SG-SECURITY
# ============================================================

def build_sg_content(row):
    return (
        f"DATASET=SG_SECURITY "
        f"NODE={get(row, ['node_id'])} "
        f"ACCESS={get(row, ['access_behavior'])} "
        f"ATTACK_TYPE={get(row, ['attack_type'])} "
        f"POLICY={get(row, ['policy_action'])} "
        f"MTD={get(row, ['mtd_strategy_used'])} "
        f"ATTACK_DETECTED={get(row, ['attack_detected'])} "
        f"VOLTAGE={get(row, ['voltage_level'])} "
        f"FREQUENCY={get(row, ['frequency_signal'])} "
        f"POWER_FLOW={get(row, ['power_flow'])} "
        f"REACTIVE_POWER={get(row, ['reactive_power'])} "
        f"COMM_SIZE={get(row, ['communication_log_size'])} "
        f"THREAT_PROB={get(row, ['threat_probability'])} "
        f"RISK_SCORE={get(row, ['risk_score'])} "
        f"UNCERTAINTY={get(row, ['uncertainty'])} "
        f"TEMPORAL_ENTROPY={get(row, ['temporal_entropy'])} "
        f"SPECTRAL_ENERGY={get(row, ['spectral_energy'])} "
        f"SPATIAL_CORR={get(row, ['spatial_correlation'])}"
    )


def build_sg_template(row):
    return (
        "DATASET=SG_SECURITY "
        "NODE=<ID> "
        f"ACCESS={get(row, ['access_behavior'])} "
        f"ATTACK_TYPE={get(row, ['attack_type'])} "
        f"POLICY={get(row, ['policy_action'])} "
        f"MTD={get(row, ['mtd_strategy_used'])} "
        "ATTACK_DETECTED=<NUMBER> "
        "VOLTAGE=<NUMBER> "
        "FREQUENCY=<NUMBER> "
        "POWER_FLOW=<NUMBER> "
        "REACTIVE_POWER=<NUMBER> "
        "COMM_SIZE=<NUMBER> "
        "THREAT_PROB=<NUMBER> "
        "RISK_SCORE=<NUMBER> "
        "UNCERTAINTY=<NUMBER> "
        "TEMPORAL_ENTROPY=<NUMBER> "
        "SPECTRAL_ENERGY=<NUMBER> "
        "SPATIAL_CORR=<NUMBER>"
    )


# ============================================================
# SWAT
# ============================================================

SWAT_FIELDS = [
    "FIT101",
    "LIT101",
    "MV101",
    "P101",
    "P102",
    "AIT201",
    "AIT202",
    "AIT203",
    "FIT201",
    "DPIT301",
    "AIT503",
]


def build_swat_content(row):
    fields = [
        "DATASET=SWAT",
        "EVENT=PROCESS_STATE",
    ]

    label = get(
        row,
        ["Normal/Attack", "Label", "label", "status"],
        default="Normal"
    ).upper()

    fields.append(f"STATUS={label}")

    for field in SWAT_FIELDS:
        if field in row.index:
            fields.append(f"{field}={safe(row[field])}")

    return " ".join(fields)


def build_swat_template(row):
    fields = [
        "DATASET=<ID>",
        "EVENT=PROCESS_STATE",
    ]

    label = get(
        row,
        ["Normal/Attack", "Label", "label", "status"],
        default="Normal"
    ).upper()

    fields.append(f"STATUS={label}")

    for field in SWAT_FIELDS:
        if field in row.index:
            fields.append(f"{field}=<NUMBER>")

    return " ".join(fields)


# ============================================================
# DNP3
# ============================================================

def normalize_dnp3_event(value):
    value = str(value).strip().upper()

    if value in {
        "BENIGN",
        "NORMAL",
    }:
        return "NORMAL"

    if "MITM" in value or "DOS" in value:
        return "MITM_DOS"

    if "INFO" in value:
        return "DNP3_INFO"

    return value.replace(" ", "_")


def build_dnp3_content(row):
    event = normalize_dnp3_event(
        get(row, ["Label", "label", "Event", "event"])
    )

    return (
        f"SRC={get(row, ['Src IP', 'Source IP', 'src_ip', 'source_ip'])} "
        f"DST={get(row, ['Dst IP', 'Destination IP', 'dst_ip', 'destination_ip'])} "
        f"SPORT={get(row, ['Src Port', 'Source Port', 'src_port', 'sport'])} "
        f"DPORT={get(row, ['Dst Port', 'Destination Port', 'dst_port', 'dport'])} "
        f"PROTO={get(row, ['Protocol', 'protocol', 'Proto', 'proto'])} "
        f"REQ_FUNC={get(row, ['mostCommonREQ_FUNC_CODE', 'REQ_FUNC', 'request_func_code'])} "
        f"RESP_FUNC={get(row, ['mostCommonRESP_FUNC_CODE', 'RESP_FUNC', 'response_func_code'])} "
        f"EVENT={event}"
    )


def build_dnp3_template(row):
    event = normalize_dnp3_event(
        get(row, ["Label", "label", "Event", "event"])
    )

    req = get(
        row,
        ["mostCommonREQ_FUNC_CODE", "REQ_FUNC", "request_func_code"]
    )

    resp = get(
        row,
        ["mostCommonRESP_FUNC_CODE", "RESP_FUNC", "response_func_code"]
    )

    if req == "UNKNOWN":
        req = "<DNP3_FUNC>"

    if resp == "UNKNOWN":
        resp = "<DNP3_FUNC>"

    return (
        "SRC=<IP> "
        "DST=<IP> "
        "SPORT=<NUMBER> "
        "DPORT=<NUMBER> "
        "PROTO=<NUMBER> "
        f"REQ_FUNC={req} "
        f"RESP_FUNC={resp} "
        f"EVENT={event}"
    )


# ============================================================
# OUTPUT HELPERS
# ============================================================

def to_logppt_json(rows):
    return [
        {
            "log": str(row["Content"]),
            "template": str(row["EventTemplate"])
        }
        for _, row in rows.iterrows()
    ]


def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False
        )


def build_structured_dataset(dataset, df):
    rows = []

    for idx, row in df.iterrows():

        if dataset == "SG_SECURITY":
            content = build_sg_content(row)
            template = build_sg_template(row)

        elif dataset == "SWAT_ATTACK":
            content = build_swat_content(row)
            template = build_swat_template(row)

        elif dataset == "DNP3_BALANCED":
            content = build_dnp3_content(row)
            template = build_dnp3_template(row)

        else:
            raise ValueError(f"Unsupported dataset: {dataset}")

        rows.append({
            "LineId": idx + 1,
            "Content": content,
            "EventTemplate": template,
        })

    return pd.DataFrame(rows)


def main():
    cfg = DATASET_CONFIG[DATASET]
    raw_gt = cfg["raw_gt"]
    out_dir = cfg["out_dir"]

    if not raw_gt.exists():
        raise FileNotFoundError(
            f"Raw reference file not found:\n{raw_gt}"
        )

    df = pd.read_csv(raw_gt)
    df.columns = [str(c).strip() for c in df.columns]

    structured_df = build_structured_dataset(
        DATASET,
        df
    )

    out_dir.mkdir(parents=True, exist_ok=True)

    structured_path = (
        out_dir /
        f"{DATASET}_full.log_structured.csv"
    )

    structured_df.to_csv(
        structured_path,
        index=False
    )

    sample_df = structured_df.sample(
        frac=1,
        random_state=RANDOM_SEED
    ).reset_index(drop=True)

    train_df = sample_df.head(TRAIN_SIZE)

    valid_df = sample_df.iloc[
        TRAIN_SIZE:
        TRAIN_SIZE + VALIDATION_SIZE
    ]

    samples_dir = out_dir / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    train_file = samples_dir / "logppt_32.json"
    validation_file = out_dir / "validation.json"

    save_json(
        to_logppt_json(train_df),
        train_file
    )

    save_json(
        to_logppt_json(valid_df),
        validation_file
    )

    print(f"[DONE] Structured GT: {structured_path}")
    print(f"[DONE] Train file: {train_file}")
    print(f"[DONE] Validation file: {validation_file}")
    print(f"[INFO] Rows: {len(structured_df)}")
    print(f"[INFO] Train examples: {len(train_df)}")
    print(f"[INFO] Validation examples: {len(valid_df)}")


if __name__ == "__main__":
    main()