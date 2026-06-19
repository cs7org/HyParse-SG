import pandas as pd

INPUT = "LibreLog-main/full_dataset/security_dataset.csv"
OUTPUT = "SG_SECURITY_full.log_structured.csv"

df = pd.read_csv(INPUT)

contents = []

for _, row in df.iterrows():

    log = (
        f"DATASET=SG_SECURITY "
        f"NODE={row['node_id']} "
        f"ACCESS={row['access_behavior']} "
        f"ATTACK_TYPE={row['attack_type']} "
        f"POLICY={row['policy_action']} "
        f"MTD={row['mtd_strategy_used']} "
        f"ATTACK_DETECTED={row['attack_detected']}"
    )

    contents.append(log)

out_df = pd.DataFrame({
    "LineId": range(1, len(contents)+1),
    "Content": contents,
    "EventId": ["E1"] * len(contents),
    "EventTemplate": [
        "DATASET=SG_SECURITY NODE=<*> ACCESS=<*> ATTACK_TYPE=<*> POLICY=<*> MTD=<*> ATTACK_DETECTED=<*>"
    ] * len(contents)
})

out_df.to_csv(OUTPUT, index=False)

print(f"[DONE] Saved to {OUTPUT}")