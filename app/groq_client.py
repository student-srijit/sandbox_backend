from __future__ import annotations

import json
import os
from typing import AsyncGenerator, Dict, List

import httpx


class GroqClient:
  def __init__(self) -> None:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
      raise RuntimeError("GROQ_API_KEY is required")

    self._api_key = api_key
    self._base_url = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    self._model = os.environ.get("GROQ_MODEL", "llama3-70b-8192")

  async def complete(self, messages: List[Dict[str, str]]) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
      response = await client.post(
        f"{self._base_url}/chat/completions",
        headers={"Authorization": f"Bearer {self._api_key}"},
        json={
          "model": self._model,
          "messages": messages,
          "temperature": 0.2,
        },
      )
      if response.status_code >= 400:
        body = await response.aread()
        raise RuntimeError(
          f"Groq completion error {response.status_code}: {body.decode('utf-8', 'ignore')}"
        )
      data = response.json()
      return data["choices"][0]["message"]["content"]

  async def stream(self, messages: List[Dict[str, str]]) -> AsyncGenerator[str, None]:
    async with httpx.AsyncClient(timeout=None) as client:
      async with client.stream(
        "POST",
        f"{self._base_url}/chat/completions",
        headers={"Authorization": f"Bearer {self._api_key}"},
        json={
          "model": self._model,
          "messages": messages,
          "temperature": 0.2,
          "stream": True,
        },
      ) as response:
        if response.status_code >= 400:
          body = await response.aread()
          raise RuntimeError(
            f"Groq stream error {response.status_code}: {body.decode('utf-8', 'ignore')}"
          )
        async for line in response.aiter_lines():
          if not line or not line.startswith("data: "):
            continue
          payload = line[len("data: ") :]
          if payload.strip() == "[DONE]":
            break
          try:
            data = json.loads(payload)
            delta = data["choices"][0]["delta"].get("content")
          except (KeyError, json.JSONDecodeError):
            continue
          if delta:
            yield delta
