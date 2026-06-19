class EvaluationDataset:
    """
       Wrapper around dataset logs
       used during evaluation.
       """

    def __init__(self, logs):
        self.logs = {}

        for log in logs:
            self.logs[log.log_id] = {

                "template": log.template_label,

                "group_id": log.group_label,

                "is_anomaly": log.is_anomaly
            }

    def get_template(self, log_id):
        return self.logs[log_id]["template"]

    def get_group(self, log_id):
        return self.logs[log_id]["group_id"]

    def is_anomaly(self, log_id):
        return self.logs[log_id]["is_anomaly"]