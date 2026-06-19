import os

class LogEntry:
    """Represents a single log entry"""

    def __init__(self, log_id, raw_text):
        self.id = log_id
        self.raw= raw_text
        self.tokens = []

class LogCollector:
    """Reads logs from a file"""

    def __init__(self, file_path):
        self.file_path = file_path

    def collect(self):
        logs = []

        if not os.path.exists(self.file_path):
            raise FileNotFoundError(self.file_path)

        with open(self.file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if line:
                    logs.append(LogEntry(i, line))

        return logs