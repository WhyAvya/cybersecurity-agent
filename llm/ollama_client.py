import requests

from vuln_agent.config import load_settings


def call_qwen(prompt: str) -> str:
    """Legacy helper; endpoint and model come from central Settings."""
    settings = load_settings()

    response = requests.post(
        f"{settings.ollama_base_url.rstrip('/')}/api/generate",
        json={
            "model": settings.ollama_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": settings.ollama_temperature,
                "num_ctx": settings.ollama_num_ctx,
            },
        },
        timeout=(settings.ollama_connect_timeout_seconds, settings.ollama_timeout_seconds),
    )

    response.raise_for_status()

    data = response.json()

    return data["response"]
