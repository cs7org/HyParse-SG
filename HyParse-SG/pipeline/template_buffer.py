from collections import deque

class TemplateBuffer:

    def __init__(self):
        self.buffer = deque()

    def push(self, c):
        self.buffer.append(c)

    def pop(self):
        return self.buffer.popleft()

    def is_empty(self):
        return len(self.buffer) == 0