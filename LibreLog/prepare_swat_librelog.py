import pandas as pd
from pathlib import Path

INPUT = Path("LibreLog-main/full_dataset/swat_merged.csv")
DATASET = "SWAT_MERGED"
OUTPUT_DIR = Path("full_dataset") / DATASET
OUTPUT = OUTPUT_DIR / f"{DATASET}_full.log_structured.csv"

IMPORTANT_FIELDS = [
    "FIT101", "LIT101", "MV101", "P101", "P102",
    "AIT201", "AIT202", "AIT203", "FIT201",
    "DPIT301", "AIT503"
]

def safe(value):
    if pd.isna(value):
        return "UNKNOWN"
    return str(value).strip().replace(" ", "_")


def build_content(row, columns):
    fields = ["DATASET=SWAT"]

    for col in IMPORTANT_FIELDS:
        if col in columns:
            fields.append(f"{col}={safe(row[col])}")

    label = safe(row.get("Normal/Attack", "Normal"))
    fields.append(f"EVENT={label.upper()}")

    return " ".join(fields)


def build_template(row, columns):
    fields = ["DATASET=SWAT"]

    for col in IMPORTANT_FIELDS:
        if col in columns:
            fields.append(f"{col}=<NUMBER>")

    label = safe(row.get("Normal/Attack", "Normal"))
    fields.append(f"EVENT={label.upper()}")

    return " ".join(fields)


df = pd.read_csv(INPUT)
df.columns = [c.strip() for c in df.columns]

rows = []

for idx, row in df.iterrows():
    content = build_content(row, df.columns)
    template = build_template(row, df.columns)

    rows.append({
        "LineId": idx + 1,
        "Content": content,
        "EventId": template,
        "EventTemplate": template
    })

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
pd.DataFrame(rows).to_csv(OUTPUT, index=False)

print(f"[DONE] Saved: {OUTPUT}")