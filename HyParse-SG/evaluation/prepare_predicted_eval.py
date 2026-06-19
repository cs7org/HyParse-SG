import pandas as pd
import ast
import re

INPUT = "swat_llama3_latest_20260618_152210.csv"
OUTPUT = "swat_predicted_eval.csv"

df = pd.read_csv(INPUT)

template_col = "llm_refined_template"

out_df = pd.DataFrame({
    "LineId": range(1, len(df) + 1),
    "EventTemplate": df[template_col].astype(str)
})

out_df = out_df[["LineId", "EventTemplate"]]
out_df.to_csv(OUTPUT, index=False)

print(f"[DONE] Saved {OUTPUT}")

#=============================================================

INPUT = "sg_security_llama3_latest_20260618_152145.csv"
OUTPUT = "sg_security_predicted_eval.csv"

df = pd.read_csv(INPUT)
df.columns = [c.strip() for c in df.columns]

template_col = "llm_refined_template"

if template_col not in df.columns:
    raise ValueError(
        f"Column '{template_col}' not found. "
        f"Available columns: {list(df.columns)}"
    )

out_df = pd.DataFrame({
    "LineId": range(1, len(df) + 1),
    "EventTemplate": df[template_col].astype(str)
})

out_df["EventId"] = out_df["EventTemplate"]

out_df = out_df[["LineId", "EventId", "EventTemplate"]]

out_df.to_csv(OUTPUT, index=False)

print(f"[DONE] Saved {OUTPUT}")

#=============================================================

INPUT = "dnp3_llama3_latest_20260618_152226.csv"
OUTPUT = "dnp3_predicted_eval.csv"

TEMPLATE_COL = "llm_refined_template"

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

def normalize_template_string(value):
    text = str(value).strip()

    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, list):
                text = " ".join(str(x) for x in parsed)
        except Exception:
            pass

    return re.sub(r"\s+", " ", text).strip()


def extract_value(template, prefix, default="UNKNOWN"):
    for token in template.split():
        if token.startswith(prefix):
            value = token.split("=", 1)[1]
            if value in {"<NUMBER>", "<VALUE>", "<*>", ""}:
                return "UNKNOWN"
            return value
    return default

def normalize_code(value):
    value = str(value).strip()

    if value.endswith(".0"):
        value = value[:-2]

    if value in {"<NUMBER>", "<VALUE>", "<*>", "", "nan", "NaN"}:
        return "UNKNOWN"

    return value

def normalize_semantic_value(value):
    value = str(value).strip()

    if value in ["<NUMBER>", "<*>", "", "nan"]:
        return "UNKNOWN"

    return value

def build_canonical_template(template):
    req = normalize_semantic_value(
        extract_value(template, "REQ_FUNC=")
    )
    resp = normalize_semantic_value(
        extract_value(template, "RESP_FUNC=")
    )
    event = normalize_dnp3_event(
        extract_value(template, "EVENT=", default="NORMAL")
    )

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


def build_event_id(template):
    req = normalize_code(extract_value(template, "REQ_FUNC="))
    resp = normalize_code(extract_value(template, "RESP_FUNC="))
    event = normalize_dnp3_event(
        extract_value(template, "EVENT=", default="NORMAL")
    )

    return f"REQ={req}|RESP={resp}|EVENT={event}"


df = pd.read_csv(INPUT)
df.columns = [c.strip() for c in df.columns]

if TEMPLATE_COL not in df.columns:
    raise ValueError(
        f"Column '{TEMPLATE_COL}' not found. Available columns: {list(df.columns)}"
    )

templates = []

for value in df[TEMPLATE_COL]:
    raw_template = normalize_template_string(value)
    templates.append(build_canonical_template(raw_template))

out_df = pd.DataFrame({
    "LineId": range(1, len(templates) + 1),
    "EventTemplate": templates,
})

out_df["EventId"] = out_df["EventTemplate"].apply(build_event_id)

out_df = out_df[["LineId", "EventId", "EventTemplate"]]
out_df.to_csv(OUTPUT, index=False)

print(f"[DONE] Saved {OUTPUT}")
