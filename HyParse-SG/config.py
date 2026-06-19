class Config:

    # Drain
    MAX_DEPTH = 5
    SIM_THRESHOLD = 0.6

    # Contextual
    NGRAM_N = 3

    # Scoring
    ALPHA = 0.67
    GAMMA = 0.7

    # Decision
    FCS_THRESHOLD = 0.5
    DCS_THRESHOLD = 0.7

    # LLM
    LLM_MODELS = [
        #"llama3:8b",
        #"mistral:7b-instruct-v0.2-q4_K_M"
        #"codegemma:7b"
    ]

    LLM_STRESS_TEST = False
    LLM_DAMAGE_RATE = 0.05

    USE_CONTEXTUAL = True