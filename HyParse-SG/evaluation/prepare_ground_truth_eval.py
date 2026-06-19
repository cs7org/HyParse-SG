import pandas as pd

from evaluation.prepare_predicted_eval import normalize_dnp3_event

INPUT = "Ground_Truth_Datasets/swat_reference.csv"
OUTPUT = "Ground_Truth_Datasets/swat_ground_truth_eval.csv"

IMPORTANT_FIELDS = [
   "FIT101",
    "LIT101",
    "P101",
    "P102",
    "AIT202",
    "AIT203",
   "FIT201",
    "DPIT301",
    "AIT503"
]

df = pd.read_csv(INPUT)
df.columns = [c.strip() for c in df.columns]

template = (
    "DATASET=SWAT EVENT=PROCESS_STATE "
    + " ".join(f"{field}=<NUMBER>" for field in IMPORTANT_FIELDS)
)

out_df = pd.DataFrame({
    "LineId": range(1, len(df) + 1),
    "EventTemplate": [template] * len(df)
})

out_df.to_csv(OUTPUT, index=False)

print(f"[DONE] Saved {OUTPUT}")

#===================================================

INPUT = "Ground_Truth_Datasets/sg_security_reference.csv"
OUTPUT = "Ground_Truth_Datasets/sg_security_ground_truth_eval.csv"

df = pd.read_csv(INPUT)
df.columns = [c.strip() for c in df.columns]

template = (
    "DATASET=SG_SECURITY "
    "NODE=<*> "
    "ACCESS=<*> "
    "ATTACK_TYPE=<*> "
    "POLICY=<*> "
    "MTD=<*> "
    "ATTACK_DETECTED=<*>"
)

out_df = pd.DataFrame({
    "LineId": range(1, len(df) + 1),
    "EventId": [template] * len(df),
    "EventTemplate": [template] * len(df)
})

out_df.to_csv(OUTPUT, index=False)

print(f"[DONE] Saved {OUTPUT}")

#==============================================================

INPUT = "Ground_Truth_Datasets/dnp3_balanced_reference.csv"
OUTPUT = "Ground_Truth_Datasets/dnp3_balanced_ground_truth_eval.csv"

DNP3_EVENT_MAP = {
    "COLD_RESTART": "RESTART",
    "WARM_RESTART": "RESTART",
    "STOP_APP": "APP_CONTROL",
    "START_APP": "APP_CONTROL",
    "DISABLE_UNSOLICITED": "UNSOLICITED_CONTROL",
    "ENABLE_UNSOLICITED": "UNSOLICITED_CONTROL",
    "INIT_DATA": "DATA_INIT",
    "DNP3_INFO": "INFO",
    "DNP3_ENUMERATE": "INFO",
    "NORMAL": "NORMAL",
    "REPLAY": "REPLAY",
}

def normalize_dnp3_event(event):
    event = str(event).strip().upper()
    return DNP3_EVENT_MAP.get(event, event)

def normalize_col(col):
    return (
        str(col)
        .strip()
        .lower()
        .replace("_", "")
        .replace("-", "")
        .replace(" ", "")
        .replace("/", "")
    )


def build_column_map(df):
    return {normalize_col(col): col for col in df.columns}


def safe(value):
    if pd.isna(value):
        return "UNKNOWN"

    value = str(value).strip()

    if value == "":
        return "UNKNOWN"

    return value.replace(" ", "_")


def get(row, colmap, candidates, default="UNKNOWN"):
    for candidate in candidates:
        key = normalize_col(candidate)
        if key in colmap:
            return safe(row[colmap[key]])
    return default


def normalize_event(value):
    value = safe(value)

    if value.upper() in {"BENIGN", "NORMAL", "0"}:
        return "NORMAL"

    return value.upper()


def build_event_id(req_func, resp_func, event):
    return f"REQ={req_func}|RESP={resp_func}|EVENT={event}"


df = pd.read_csv(INPUT)
df.columns = [str(c).strip() for c in df.columns]
colmap = build_column_map(df)

templates = []
event_ids = []

for _, row in df.iterrows():

    req_func = get(
        row,
        colmap,
        [
            "mostCommonREQ_FUNC_CODE",
            "REQ_FUNC",
            "REQ_FUNC_CODE",
            "req func",
        ],
        default="UNKNOWN"
    )

    resp_func = get(
        row,
        colmap,
        [
            "mostCommonRESP_FUNC_CODE",
            "RESP_FUNC",
            "RESP_FUNC_CODE",
            "resp func",
        ],
        default="UNKNOWN"
    )

    event = normalize_dnp3_event(
        get(
            row,
            colmap,
            ["Label", "label", "Event", "event", "EVENT"],
            default="NORMAL"
        )
    )

    template = (
        "SRC=<IP> "
        "DST=<IP> "
        "SPORT=<NUMBER> "
        "DPORT=<NUMBER> "
        "PROTO=<NUMBER> "
        f"REQ_FUNC={req_func} "
        f"RESP_FUNC={resp_func} "
        f"EVENT={event}"
    )

    templates.append(template)
    event_ids.append(build_event_id(req_func, resp_func, event))


out_df = pd.DataFrame({
    "LineId": range(1, len(df) + 1),
    "EventId": event_ids,
    "EventTemplate": templates,
})

out_df.to_csv(OUTPUT, index=False)
print(f"[DONE] Saved {OUTPUT}")
