import pandas as pd

INPUT = "data/SWaT_Dataset/attack.csv"
OUTPUT = "results/output/swat_attack_spell.log"


def safe(value):
    if pd.isna(value):
        return "UNKNOWN"

    return str(value).strip().replace(" ", "_")


def get(row, candidates, default="UNKNOWN"):
    for col in candidates:
        if col in row.index:
            return safe(row[col])

    return default


df = pd.read_csv(INPUT)
df.columns = [c.strip() for c in df.columns]

with open(OUTPUT, "w", encoding="utf-8") as f:

    for _, row in df.iterrows():

        status = get(
            row,
            ["Normal/Attack", "Normal Attack", "Label", "label"],
            default="UNKNOWN"
        )

        fit101 = get(row, ["FIT101"])
        lit101 = get(row, ["LIT101"])
        mv101 = get(row, ["MV101"])
        p101 = get(row, ["P101"])
        p102 = get(row, ["P102"])
        ait201 = get(row, ["AIT201"])
        ait202 = get(row, ["AIT202"])
        ait203 = get(row, ["AIT203"])
        fit201 = get(row, ["FIT201"])
        dpit301 = get(row, ["DPIT301"])
        ait503 = get(row, ["AIT503"])

        line = (
            f"DATASET=SWAT "
            f"EVENT=PROCESS_STATE "
            f"STATUS={status} "
            f"FIT101={fit101} "
            f"LIT101={lit101} "
            f"MV101={mv101} "
            f"P101={p101} "
            f"P102={p102} "
            f"AIT201={ait201} "
            f"AIT202={ait202} "
            f"AIT203={ait203} "
            f"FIT201={fit201} "
            f"DPIT301={dpit301} "
            f"AIT503={ait503}"
        )

        f.write(line + "\n")


print(f"Saved Spell-compatible SWaT log file: {OUTPUT}")