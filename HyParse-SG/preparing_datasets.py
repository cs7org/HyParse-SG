import pandas as pd

INPUT = "data/DNP3_Dataset/Training_Testing_Balanced_CSV_Files/CICFlowMeter/CICFlowMeter_Testing_Balanced.csv"
OUTPUT = "results/output/dnp3_balanced_drain.log"

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

        src = get(
            row,
            ["Src IP", "Source IP", "source IP", "src_ip", "source_ip"]
        )

        dst = get(
            row,
            ["Dst IP", "Destination IP", "destination IP", "dst_ip", "destination_ip"]
        )

        sport = get(
            row,
            ["Src Port", "Source Port", "source port", "src_port", "sport"]
        )

        dport = get(
            row,
            ["Dst Port", "Destination Port", "destination port", "dst_port", "dport"]
        )

        proto = get(
            row,
            ["Protocol", "protocol", "Proto", "proto"]
        )

        duration = get(
            row,
            ["Flow Duration", "duration", "Duration"]
        )

        total_fwd = get(
            row,
            ["Tot Fwd Pkts", "TotalFwdPkts", "Total Fwd Packets"]
        )

        total_bwd = get(
            row,
            ["Tot Bwd Pkts", "TotalBwdPkts", "Total Backward Packets"]
        )

        flow_bytes = get(
            row,
            ["Flow Byts/s", "Flow Bytes/s", "DLflowBytes/sec", "TRflowBytes/sec", "APPflowBytes/sec"]
        )

        flow_pkts = get(
            row,
            ["Flow Pkts/s", "Flow Packets/s", "FlowPkts/sec"]
        )

        req_func = get(
            row,
            ["mostCommonREQ_FUNC_CODE", "REQ_FUNC", "request_func_code"]
        )

        resp_func = get(
            row,
            ["mostCommonRESP_FUNC_CODE", "RESP_FUNC", "response_func_code"]
        )

        label = get(
            row,
            ["Label", "label", "Event", "event"],
            default="UNKNOWN"
        )

        line = (
            f"SRC={src} "
            f"DST={dst} "
            f"SPORT={sport} "
            f"DPORT={dport} "
            f"PROTO={proto} "
            f"FLOW_DURATION={duration} "
            f"TOT_FWD_PKTS={total_fwd} "
            f"TOT_BWD_PKTS={total_bwd} "
            f"FLOW_BYTES_S={flow_bytes} "
            f"FLOW_PKTS_S={flow_pkts} "
            f"REQ_FUNC={req_func} "
            f"RESP_FUNC={resp_func} "
            f"EVENT={label}"
        )

        f.write(line + "\n")


print(f"Saved Drain-compatible DNP3 log file: {OUTPUT}")