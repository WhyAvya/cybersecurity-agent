import pytest
import requests

from vuln_agent.config import Settings
from vuln_agent.exceptions import LLMError, SchemaParseError
from vuln_agent.llm import OllamaClient
from vuln_agent.schemas import AgentAnalysis


class Response:
    def __init__(self, payload, status_error=None):
        self.payload = payload
        self.status_error = status_error

    def raise_for_status(self):
        if self.status_error:
            raise self.status_error

    def json(self):
        return self.payload


class Session:
    def __init__(self, response):
        self.response = response

    def post(self, *args, **kwargs):
        return self.response

    def get(self, *args, **kwargs):
        return Response({"models": [{"name": "qwen2.5-coder:7b"}]})


def test_ollama_structured_success():
    response = Response(
        {
            "model": "qwen2.5-coder:7b",
            "response": '{"verdict":"TP","confidence":0.8,"normalized_cwe":"CWE-089","reasoning_summary":"flow reaches sink"}',
        }
    )
    result = OllamaClient(Settings(), session=Session(response)).generate_structured("prompt", AgentAnalysis)
    assert result.parsed.verdict.value == "TP"


def test_ollama_schema_failure_is_not_safe():
    response = Response({"response": '{"verdict":"SAFE","confidence":0.8,"reasoning_summary":"bad"}'})
    with pytest.raises(SchemaParseError):
        OllamaClient(Settings(), session=Session(response)).generate_structured("prompt", AgentAnalysis)


def test_ollama_connection_failure():
    class BrokenSession:
        def post(self, *args, **kwargs):
            raise requests.ConnectionError("down")

    with pytest.raises(LLMError):
        OllamaClient(Settings(ollama_max_retries=0), session=BrokenSession()).generate_structured("prompt", AgentAnalysis)


def test_ollama_healthcheck_rejects_empty_model_list():
    class EmptySession:
        def get(self, *args, **kwargs):
            return Response({"models": []})

    status = OllamaClient(Settings(ollama_model="qwen2.5-coder:7b"), session=EmptySession()).healthcheck()
    assert not status.ok
    assert "no models" in status.message


def test_ollama_healthcheck_requires_configured_model():
    class WrongModelSession:
        def get(self, *args, **kwargs):
            return Response({"models": [{"name": "other:latest"}]})

    status = OllamaClient(Settings(ollama_model="qwen2.5-coder:7b"), session=WrongModelSession()).healthcheck()
    assert not status.ok
    assert "Model not listed" in status.message
