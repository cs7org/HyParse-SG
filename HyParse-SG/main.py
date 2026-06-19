from parsing.tokens import TokenClassifier
from parsing.drain import DrainParser
from contextual.context_parser import ContextualParser
from pipeline.template_buffer import TemplateBuffer
from pipeline.candidate import TemplateCandidate
from pipeline.decision import DecisionEngine

def run_pipeline(logs):

    classifier = TokenClassifier()
    drain = DrainParser(classifier)
    context = ContextualParser(classifier)

    buffer = TemplateBuffer()

    for log in logs:
        template = drain.parse(log)
        ctx = context.process(log, template)

        candidate = TemplateCandidate(
            log_id=log.log_id,
            raw_log=log.raw_text,
            template=template.tokens,
            refined_template=ctx["refined_template"],
            device=ctx["device"],
            dcs={"DCS": 0.8},
            ccs={"CCS": 0.7},
            fcs=0.5
        )

        buffer.push(candidate)

    engine = DecisionEngine(threshold=0.5)
    return engine.process(buffer)