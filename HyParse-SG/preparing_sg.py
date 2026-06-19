import pandas as pd


INPUT = "data/SG-Security_Dataset/security_dataset.csv"
OUTPUT = "results/output/sg_security_spell.log"


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

        node = get(row, ["node_id", "NODE", "Node"])
        access = get(row, ["access_behavior", "ACCESS"])
        attack_type = get(row, ["attack_type", "ATTACK_TYPE"])
        policy = get(row, ["policy_action", "POLICY"])
        mtd = get(row, ["mtd_strategy_used", "MTD"])
        attack_detected = get(row, ["attack_detected", "ATTACK_DETECTED"])

        voltage = get(row, ["voltage_level", "VOLTAGE"])
        frequency = get(row, ["frequency_signal", "FREQUENCY"])
        power_flow = get(row, ["power_flow", "POWER_FLOW"])
        reactive_power = get(row, ["reactive_power", "REACTIVE_POWER"])
        comm_size = get(row, ["communication_log_size", "COMM_SIZE"])

        threat_prob = get(row, ["threat_probability", "THREAT_PROB"])
        risk_score = get(row, ["risk_score", "RISK_SCORE"])
        uncertainty = get(row, ["uncertainty", "UNCERTAINTY"])

        temporal_entropy = get(row, ["temporal_entropy", "TEMPORAL_ENTROPY"])
        spectral_energy = get(row, ["spectral_energy", "SPECTRAL_ENERGY"])
        spatial_corr = get(row, ["spatial_correlation", "SPATIAL_CORR"])

        line = (
            f"DATASET=SG_SECURITY "
            f"NODE={node} "
            f"ACCESS={access} "
            f"ATTACK_TYPE={attack_type} "
            f"POLICY={policy} "
            f"MTD={mtd} "
            f"ATTACK_DETECTED={attack_detected} "
            f"VOLTAGE={voltage} "
            f"FREQUENCY={frequency} "
            f"POWER_FLOW={power_flow} "
            f"REACTIVE_POWER={reactive_power} "
            f"COMM_SIZE={comm_size} "
            f"THREAT_PROB={threat_prob} "
            f"RISK_SCORE={risk_score} "
            f"UNCERTAINTY={uncertainty} "
            f"TEMPORAL_ENTROPY={temporal_entropy} "
            f"SPECTRAL_ENERGY={spectral_energy} "
            f"SPATIAL_CORR={spatial_corr}"
        )

        f.write(line + "\n")


print(f"Saved Spell-compatible SG-Security log file: {OUTPUT}")