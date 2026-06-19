import pandas as pd

INPUT = "LibreLog-main/full_dataset/dnp3_info.csv"
OUTPUT = "DNP3_INFO_full.log_structured.csv"


def safe(value):
    if pd.isna(value):
        return "UNKNOWN"

    return str(value).strip().replace(" ", "_")


def get(row, candidates):
    for col in candidates:
        if col in row.index:
            return safe(row[col])

    return "UNKNOWN"


df = pd.read_csv(INPUT)
df.columns = [c.strip() for c in df.columns]

contents = []
templates = []

for _, row in df.iterrows():

    event = get(row, ["Label", "label", "Event", "event"])

    log = (
        f"SRC={get(row, ['Src IP', 'source IP', 'Source IP'])} "
        f"DST={get(row, ['Dst IP', 'destination IP', 'Destination IP'])} "
        f"SPORT={get(row, ['Src Port', 'source port', 'Source Port'])} "
        f"DPORT={get(row, ['Dst Port', 'destination port', 'Destination Port'])} "
        f"PROTO={get(row, ['Protocol', 'protocol'])} "
        f"Flow Duration={get(row, ['Flow Duration', 'duration', 'Duration'])} "
        f"Tot Fwd Pkts={get(row, ['Tot Fwd Pkts', 'TotalFwdPkts'])} "
        f"Tot Bwd Pkts={get(row, ['Tot Bwd Pkts', 'TotalBwdPkts'])} "
        f"Flow Byts/s={get(row, ['Flow Byts/s', 'Flow Bytes/s', 'DLflowBytes/sec', 'TRflowBytes/sec', 'APPflowBytes/sec'])} "
        f"Flow Pkts/s={get(row, ['Flow Pkts/s', 'FlowPkts/sec'])} "
        f"REQ_FUNC={get(row, ['mostCommonREQ_FUNC_CODE', 'REQ_FUNC'])} "
        f"RESP_FUNC={get(row, ['mostCommonRESP_FUNC_CODE', 'RESP_FUNC'])} "
        f"EVENT={event}"
    )

    template = (
        "SRC=<IP> "
        "DST=<IP> "
        "SPORT=<NUMBER> "
        "DPORT=<NUMBER> "
        "PROTO=<NUMBER> "
        "Flow Duration=<NUMBER> "
        "Tot Fwd Pkts=<NUMBER> "
        "Tot Bwd Pkts=<NUMBER> "
        "Flow Byts/s=<NUMBER> "
        "Flow Pkts/s=<NUMBER> "
        "REQ_FUNC=<NUMBER> "
        "RESP_FUNC=<NUMBER> "
        f"EVENT={event}"
    )

    contents.append(log)
    templates.append(template)


out_df = pd.DataFrame({
    "LineId": range(1, len(contents) + 1),
    "Content": contents,
    "EventId": templates,
    "EventTemplate": templates
})

out_df.to_csv(OUTPUT, index=False)

print(f"[DONE] Saved to {OUTPUT}")