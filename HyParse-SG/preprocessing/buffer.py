from collections import deque

class NormalizedLogBuffer:
    def __init__(self):
        self.buffer = deque()

    def push(self, log):
        self.buffer.append(log)

    def pop(self):
        return self.buffer.popleft()

    def is_empty(self):
        return len(self.buffer) == 0