"""
ai/llm_client.py

Provider-agnostic LLM client. Talks to any model via plain REST calls,
no vendor SDK required. Supports two API shapes:

  - "anthropic"        -> Anthropic Messages API (api.anthropic.com or
                           a compatible endpoint)
  - "openai_compatible" -> OpenAI-style Chat Completions API. This shape
                           is also used by OpenAI itself, and by local
                           servers like Ollama or LM Studio, so pointing
                           base_url at "http://localhost:11434/v1" (Ollama)
                           works with zero code changes.

Each model used by the project (model 1, model 2) has its own config,
read from .env, so you can mix providers freely (e.g. Claude vs a local
Llama model).
"""

import requests


def call_model(
    provider: str,
    model_name: str,
    system_prompt: str,
    messages: list[dict],
    api_key: str = "",
    base_url: str = "",
    max_tokens: int = 500,
    timeout: int = 60,
) -> str:
    """
    Send a chat request to a model and return its text reply.

    messages: list of {"role": "user" | "assistant", "content": "..."}
    (system prompt is passed separately, not as part of messages)
    """
    if provider == "anthropic":
        return _call_anthropic(
            model_name, system_prompt, messages, api_key, base_url, max_tokens, timeout
        )
    elif provider == "openai_compatible":
        return _call_openai_compatible(
            model_name, system_prompt, messages, api_key, base_url, max_tokens, timeout
        )
    else:
        raise ValueError(f"Unknown provider: {provider}. Use 'anthropic' or 'openai_compatible'.")


def _call_anthropic(model_name, system_prompt, messages, api_key, base_url, max_tokens, timeout):
    url = (base_url or "https://api.anthropic.com") + "/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": model_name,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": messages,
    }

    response = requests.post(url, headers=headers, json=body, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    # content is a list of blocks (usually one text block)
    text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
    return "\n".join(text_blocks).strip()


def _call_openai_compatible(model_name, system_prompt, messages, api_key, base_url, max_tokens, timeout):
    url = (base_url or "https://api.openai.com/v1") + "/chat/completions"
    headers = {"content-type": "application/json"}
    if api_key:
        # Local servers (e.g. Ollama) usually don't need a real key.
        headers["Authorization"] = f"Bearer {api_key}"

    full_messages = [{"role": "system", "content": system_prompt}] + messages
    body = {
        "model": model_name,
        "messages": full_messages,
        "max_tokens": max_tokens,
    }

    response = requests.post(url, headers=headers, json=body, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    return data["choices"][0]["message"]["content"].strip()
