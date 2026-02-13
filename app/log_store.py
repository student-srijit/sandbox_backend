from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx


class LogStore:
    def __init__(self) -> None:
        url = os.environ.get("UPSTASH_REDIS_REST_URL")
        token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
        if not url or not token:
            raise RuntimeError("UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are required")

        self._url = url.rstrip("/")
        self._token = token
        self._key = os.environ.get("LOG_KEY", "mp:logs")
        self._max = int(os.environ.get("LOG_MAX", "200"))

    async def _command(self, command: List[Any]) -> Any:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                self._url,
                headers={"Authorization": f"Bearer {self._token}"},
                json=command,
            )
            response.raise_for_status()
            data = response.json()
            if "error" in data:
                raise RuntimeError(data["error"])
            return data.get("result")

    async def _pipeline(self, commands: List[List[Any]]) -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{self._url}/pipeline",
                headers={"Authorization": f"Bearer {self._token}"},
                json=commands,
            )
            response.raise_for_status()
            data = response.json()
            for entry in data:
                if "error" in entry:
                    raise RuntimeError(entry["error"])

    async def add_log(self, entry: Dict[str, Any]) -> None:
        payload = json.dumps(entry, separators=(",", ":"))
        await self._pipeline(
            [
                ["LPUSH", self._key, payload],
                ["LTRIM", self._key, 0, self._max - 1],
                ["INCR", "mp:count"],
            ]
        )

    async def get_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        result = await self._command(["LRANGE", self._key, 0, max(limit - 1, 0)])
        if not result:
            return []
        logs: List[Dict[str, Any]] = []
        for item in result:
            try:
                logs.append(json.loads(item))
            except json.JSONDecodeError:
                continue
        return logs

    async def get_total(self) -> int:
        result = await self._command(["GET", "mp:count"])
        if result is None:
            return 0
        try:
            return int(result)
        except (TypeError, ValueError):
            return 0


def detect_alert(command: str) -> Tuple[Optional[str], Optional[str]]:
    lowered = command.lower()
    if "rm -rf /" in lowered:
        return ("Destructive wipe attempt detected", "high")
    if "cat /etc/passwd" in lowered or "cat /etc/shadow" in lowered:
        return ("Credential file access attempt", "high")
    if lowered.startswith("sudo"):
        return ("Privilege escalation attempt", "medium")
    if lowered.startswith("ls") or lowered.startswith("dir"):
        return ("Directory enumeration detected", "low")
    if "curl" in lowered or "wget" in lowered:
        return ("External fetch attempt", "low")
    return (None, None)


def build_log_entry(
    *,
    ip: str,
    session_id: str,
    command: str,
    mode: str,
) -> Dict[str, Any]:
    alert, severity = detect_alert(command)
    return {
        "id": f"evt_{int(time.time() * 1000)}",
        "ts": int(time.time() * 1000),
        "ip": ip,
        "session_id": session_id,
        "command": command,
        "mode": mode,
        "alert": alert,
        "severity": severity,
    }
