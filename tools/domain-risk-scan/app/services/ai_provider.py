from __future__ import annotations

import json
from typing import Any


class AIProviderError(Exception):
    pass


def generate_json_from_llm(prompt: str) -> dict[str, Any]:
    raise AIProviderError("AI provider not configured yet")