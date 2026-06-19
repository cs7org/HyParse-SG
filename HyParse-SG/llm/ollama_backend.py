import requests
from llm.backend import LLMBackend

class OllamaBackend(LLMBackend):

    def __init__(
        self,
        model_name,
        host="http://localhost:11434"
    ):

        self.model_name = model_name
        self.host = host

    def generate(self, prompt):

        url = f"{self.host}/api/generate"

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,

            # deterministic generation
            "options": {
                "temperature": 0.0,
                "top_p": 1.0,
                "top_k": 1,
                "repeat_penalty": 1.0,
                "seed": 42
            }
        }

        response = requests.post(url, json=payload)

        response.raise_for_status()

        data = response.json()

        return data["response"].strip()