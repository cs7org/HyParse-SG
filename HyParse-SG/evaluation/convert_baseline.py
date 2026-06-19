from evaluation.baseline_adapter import BaselineAdapter

# Drain
BaselineAdapter.convert_parser_output(
    input_csv="dnp3_balanced_drain.log_structured.csv",
    output_csv="eval_ready/dnp3_drain.csv",
    parser_name="drain",
    dataset_name="DNP3",
)

BaselineAdapter.convert_parser_output(
    input_csv="sg_security_drain.log_structured.csv",
    output_csv="eval_ready/sg_security_drain.csv",
    parser_name="drain",
    dataset_name="SG_SECURITY",
)

BaselineAdapter.convert_parser_output(
    input_csv="swat_attack_drain.log_structured.csv",
    output_csv="eval_ready/swat_drain.csv",
    parser_name="drain",
    dataset_name="SWAT",
)

# Spell
BaselineAdapter.convert_parser_output(
    input_csv="dnp3_balanced_spell.log_structured.csv",
    output_csv="eval_ready/dnp3_spell.csv",
    parser_name="spell",
    dataset_name="DNP3",
)

BaselineAdapter.convert_parser_output(
    input_csv="sg_security_spell.log_structured.csv",
    output_csv="eval_ready/sg_security_spell.csv",
    parser_name="spell",
    dataset_name="SG_SECURITY",
)

BaselineAdapter.convert_parser_output(
    input_csv="swat_attack_spell.log_structured.csv",
    output_csv="eval_ready/swat_spell.csv",
    parser_name="spell",
    dataset_name="SWAT",
)

# LibreLog
BaselineAdapter.convert_parser_output(
    input_csv="dnp3_librelog_group.csv",
    output_csv="eval_ready/dnp3_librelog.csv",
    parser_name="librelog",
    dataset_name="DNP3",
)

BaselineAdapter.convert_parser_output(
    input_csv="sg-security_libreloggroup.csv",
    output_csv="eval_ready/sg_security_librelog.csv",
    parser_name="librelog",
    dataset_name="SG_SECURITY",
)

BaselineAdapter.convert_parser_output(
    input_csv="swat_librelog_group.csv",
    output_csv="eval_ready/swat_librelog.csv",
    parser_name="librelog",
    dataset_name="SWAT",
)

# LogPPT
BaselineAdapter.convert_parser_output(
    input_csv="DNP3_BALANCED_full.log_structured.csv",
    output_csv="eval_ready/dnp3_logppt.csv",
    parser_name="logppt",
    dataset_name="DNP3",
)

BaselineAdapter.convert_parser_output(
    input_csv="SG_SECURITY_full.log_structured.csv",
    output_csv="eval_ready/sg_security_logppt.csv",
    parser_name="logppt",
    dataset_name="SG_SECURITY",
)

BaselineAdapter.convert_parser_output(
    input_csv="SWAT_ATTACK_full.log_structured.csv",
    output_csv="eval_ready/swat_logppt.csv",
    parser_name="logppt",
    dataset_name="SWAT",
)