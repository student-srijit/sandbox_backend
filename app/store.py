from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class Message:
  role: str
  content: str


class SessionStore:
  def __init__(self, max_history: int = 20) -> None:
    self._history: Dict[str, List[Message]] = defaultdict(list)
    self._max_history = max_history

  def append(self, session_id: str, role: str, content: str) -> None:
    history = self._history[session_id]
    history.append(Message(role=role, content=content))
    if len(history) > self._max_history:
      self._history[session_id] = history[-self._max_history :]

  def get(self, session_id: str) -> List[Message]:
    return list(self._history.get(session_id, []))

  def reset(self, session_id: str) -> None:
    if session_id in self._history:
      self._history[session_id] = []
