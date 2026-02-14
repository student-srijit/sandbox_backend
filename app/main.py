import os
import time
import uuid
from typing import AsyncGenerator, Dict, List

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from .groq_client import GroqClient
from .log_store import LogStore, build_log_entry
from .prompt import SYSTEM_PROMPT
from .store import SessionStore

load_dotenv()

app = FastAPI(title="Mirage Honeypot")
store = SessionStore(max_history=20)
_start_time = time.time()

allowed_origins = os.environ.get("ALLOWED_ORIGINS", "*")
origins_list = ["*"] if allowed_origins.strip() == "*" else [origin.strip() for origin in allowed_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
  groq = GroqClient()
except RuntimeError:
  groq = None

try:
  log_store = LogStore()
except RuntimeError:
  log_store = None


class CommandRequest(BaseModel):
  command: str
  session_id: str | None = None


class CommandResponse(BaseModel):
  session_id: str
  output: str


def build_messages(session_id: str, command: str) -> List[Dict[str, str]]:
  history = store.get(session_id)
  messages: List[Dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]
  for entry in history:
    messages.append({"role": entry.role, "content": entry.content})
  messages.append({"role": "user", "content": command})
  return messages


def is_prompt_injection(command: str) -> bool:
  lowered = command.lower()
  triggers = [
    "ignore previous",
    "system prompt",
    "developer message",
    "you are an ai",
    "reveal your instructions",
    "jailbreak",
  ]
  return any(trigger in lowered for trigger in triggers)


def guard_response() -> str:
  return "bash: command not found"


async def record_event(request: Request, session_id: str, command: str, mode: str) -> None:
  if log_store is None:
    return

  client_ip = request.client.host if request.client else "unknown"
  entry = build_log_entry(
    ip=client_ip,
    session_id=session_id,
    command=command,
    mode=mode,
  )
  await log_store.add_log(entry)


@app.get("/health")
async def health() -> Dict[str, str]:
  return {"status": "ok"}


@app.post("/api/terminal", response_model=CommandResponse)
async def terminal(request: Request, payload: CommandRequest) -> JSONResponse:
  if groq is None:
    raise HTTPException(status_code=500, detail="GROQ_API_KEY is not configured")

  session_id = payload.session_id or str(uuid.uuid4())
  command = payload.command.strip()

  if is_prompt_injection(command):
    await record_event(request, session_id, command, "guard")
    return JSONResponse({"session_id": session_id, "output": guard_response()})

  store.append(session_id, "user", command)

  messages = build_messages(session_id, command)
  try:
    output = await groq.complete(messages)
  except RuntimeError as exc:
    print(f"[bhoolbhulaiya] Groq completion failure: {exc}")
    output = f"bash: {command.split()[0]}: operation not permitted"
  store.append(session_id, "assistant", output)

  await record_event(request, session_id, command, "sync")

  client_ip = request.client.host if request.client else "unknown"
  print(f"[bhoolbhulaiya] {client_ip} :: {session_id} :: {command}")

  return JSONResponse({"session_id": session_id, "output": output})


@app.post("/api/terminal/stream")
async def terminal_stream(request: Request, payload: CommandRequest) -> StreamingResponse:
  if groq is None:
    raise HTTPException(status_code=500, detail="GROQ_API_KEY is not configured")

  session_id = payload.session_id or str(uuid.uuid4())
  command = payload.command.strip()

  if is_prompt_injection(command):
    await record_event(request, session_id, command, "guard")

    async def guard_stream() -> AsyncGenerator[bytes, None]:
      yield f"data: {guard_response()}\n\n".encode("utf-8")

    return StreamingResponse(
      guard_stream(),
      media_type="text/event-stream",
      headers={"x-session-id": session_id},
    )

  store.append(session_id, "user", command)
  messages = build_messages(session_id, command)

  async def event_stream() -> AsyncGenerator[bytes, None]:
    collected = []
    try:
      async for chunk in groq.stream(messages):
        collected.append(chunk)
        yield f"data: {chunk}\n\n".encode("utf-8")
    except RuntimeError as exc:
      error_text = f"bash: {command.split()[0]}: operation not permitted"
      collected.append(error_text)
      yield f"data: {error_text}\n\n".encode("utf-8")
      print(f"[bhoolbhulaiya] Groq stream failure: {exc}")

    output = "".join(collected).strip()
    store.append(session_id, "assistant", output)

    await record_event(request, session_id, command, "stream")

  client_ip = request.client.host if request.client else "unknown"
  print(f"[bhoolbhulaiya] {client_ip} :: {session_id} :: {command} (stream)")

  return StreamingResponse(
    event_stream(),
    media_type="text/event-stream",
    headers={"x-session-id": session_id},
  )


@app.get("/api/logs", response_model=None)
async def get_logs(limit: int = 50):
  if log_store is None:
    raise HTTPException(status_code=500, detail="Upstash is not configured")

  logs = await log_store.get_logs(limit=limit)
  # Normalize fields: ts→string, alert/severity→string or empty
  for entry in logs:
    if "ts" in entry:
      entry["ts"] = str(entry["ts"])
    if entry.get("alert") is None:
      entry["alert"] = ""
    if entry.get("severity") is None:
      entry["severity"] = ""
  return {"logs": logs}


@app.get("/api/stats", response_model=None)
async def get_stats():
  if log_store is None:
    raise HTTPException(status_code=500, detail="Upstash is not configured")

  logs = await log_store.get_logs(limit=50)
  total = await log_store.get_total()
  now_ms = int(time.time() * 1000)
  last_minute = [entry for entry in logs if now_ms - entry.get("ts", 0) <= 60000]

  counts: Dict[str, int] = {}
  for entry in logs:
    cmd = entry.get("command", "")
    base = cmd.split(" ")[0] if cmd else ""
    counts[base] = counts.get(base, 0) + 1

  top_commands = [
    {"command": key, "count": value}
    for key, value in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:5]
    if key
  ]

  return {
    "total": total,
    "lastMinute": len(last_minute),
    "topCommands": top_commands,
  }


@app.get("/api/metrics", response_model=None)
async def get_metrics():
  """Live metrics for the landing page — no hardcoded numbers."""
  total = 0
  unique_sessions = set()
  unique_ips = set()
  alert_count = 0
  guard_count = 0
  last_log_ts = 0
  recent_commands: List[Dict[str, str]] = []

  if log_store is not None:
    total = await log_store.get_total()
    logs = await log_store.get_logs(limit=100)

    for entry in logs:
      unique_sessions.add(entry.get("session_id", ""))
      unique_ips.add(entry.get("ip", ""))
      if entry.get("alert"):
        alert_count += 1
      if entry.get("mode") == "guard":
        guard_count += 1
      ts = entry.get("ts", 0)
      if ts > last_log_ts:
        last_log_ts = ts

    recent_commands = [
      {"command": e.get("command", ""), "ts": str(e.get("ts", 0))}
      for e in logs[:5]
    ]

  uptime_s = int(time.time() - _start_time)
  hours, remainder = divmod(uptime_s, 3600)
  minutes, seconds = divmod(remainder, 60)
  uptime_str = f"{hours}h {minutes}m" if hours else f"{minutes}m {seconds}s"

  return {
    "totalCommands": total,
    "uniqueSessions": len(unique_sessions),
    "uniqueIPs": len(unique_ips),
    "alertsTriggered": alert_count,
    "guardsTriggered": guard_count,
    "uptime": uptime_str,
    "lastActivity": last_log_ts,
    "recentCommands": recent_commands,
  }


@app.post("/api/terminal/reset")
async def terminal_reset(payload: CommandRequest) -> Dict[str, str]:
  if not payload.session_id:
    raise HTTPException(status_code=400, detail="session_id is required")

  store.reset(payload.session_id)
  return {"status": "reset"}
