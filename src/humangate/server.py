"""Localhost approval daemon.

Two planes, strictly separated:
- Agent plane (no auth, on the plain root): create requests + poll status.
  It has NO decision endpoint — an agent using the documented interface cannot
  approve or dismiss its own request, because there is no route for it.
- Human plane: the approval desk lives under a capability URL
  /desk/<256-bit-token>/ printed to the human's terminal at startup. Decisions
  require the token both in the path and as a Bearer header.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .audit import AuditLog
from .notifier import notify

RISKS = ("low", "medium", "high", "critical")
DEFAULT_TIMEOUT = 300


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


class ApprovalState:
    def __init__(self, data_dir: str, token: str | None = None):
        self.token = token or secrets.token_hex(32)
        self.audit = AuditLog(f"{data_dir}/audit.jsonl")
        self._requests: dict[str, dict] = {}
        self._lock = threading.Lock()

    # -- agent plane -----------------------------------------------------
    def create_request(self, title: str, detail: str = "", risk: str = "medium",
                       agent: str = "", timeout_secs: int = DEFAULT_TIMEOUT) -> dict:
        if risk not in RISKS:
            raise ValueError(f"risk must be one of {RISKS}")
        timeout_secs = max(1, min(int(timeout_secs), 86400))
        now = time.time()
        req = {
            "id": _new_id(),
            "title": title[:200],
            "detail": detail[:4000],
            "risk": risk,
            "agent": agent[:120],
            "created_at": now,
            "expires_at": now + timeout_secs,
            "timeout_secs": timeout_secs,
            "status": "pending",          # pending | approved | denied
            "decided_at": None,
            "decided_via": None,          # "desk" | "timeout" | "cli"
            "decision_note": "",
        }
        with self._lock:
            self._requests[req["id"]] = req
        self.audit.append("request.created", request_id=req["id"], title=req["title"],
                          risk=req["risk"], agent=req["agent"],
                          timeout_secs=timeout_secs)
        notify("human-gate: approval needed",
               f"[{risk}] {title[:80]}")
        return dict(req)

    def sweep_expiries(self) -> None:
        now = time.time()
        expired = []
        with self._lock:
            for req in self._requests.values():
                if req["status"] == "pending" and req["expires_at"] <= now:
                    req["status"] = "denied"
                    req["decided_at"] = now
                    req["decided_via"] = "timeout"
                    expired.append(req["id"])
        for rid in expired:
            self.audit.append("request.timeout", request_id=rid,
                              note="default-deny: human did not respond in time")

    def get_request(self, rid: str) -> dict | None:
        self.sweep_expiries()
        with self._lock:
            req = self._requests.get(rid)
            return dict(req) if req else None

    def list_requests(self, pending_only: bool = True) -> list[dict]:
        self.sweep_expiries()
        with self._lock:
            reqs = [dict(r) for r in self._requests.values()
                    if not pending_only or r["status"] == "pending"]
        reqs.sort(key=lambda r: r["created_at"])
        return reqs

    # -- human plane -----------------------------------------------------
    def decide(self, rid: str, approve: bool, note: str = "",
               via: str = "desk") -> dict | None:
        self.sweep_expiries()
        with self._lock:
            req = self._requests.get(rid)
            if req is None or req["status"] != "pending":
                return None
            req["status"] = "approved" if approve else "denied"
            req["decided_at"] = time.time()
            req["decided_via"] = via
            req["decision_note"] = note[:500]
            out = dict(req)
        self.audit.append("decision.approved" if approve else "decision.denied",
                          request_id=rid, via=via, note=out["decision_note"])
        return out

    def check_token(self, candidate: str) -> bool:
        return hmac.compare_digest(candidate or "", self.token)


DESK_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>human-gate approval desk</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;background:#fafafa}
h1{font-size:1.4rem}
.card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:1rem 1.2rem;margin:1rem 0;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.risk{display:inline-block;padding:.15rem .6rem;border-radius:999px;font-size:.8rem;font-weight:600;color:#fff}
.low{background:#2f9e44}.medium{background:#e67700}.high{background:#d6336c}.critical{background:#000}
.meta{color:#666;font-size:.85rem;margin:.4rem 0}
.detail{white-space:pre-wrap;background:#f4f4f4;border-radius:6px;padding:.6rem;margin:.6rem 0;font-size:.9rem}
.btn{border:none;border-radius:8px;padding:.6rem 1.4rem;font-size:1rem;cursor:pointer;margin-right:.6rem}
.approve{background:#2f9e44;color:#fff}.deny{background:#c92a2a;color:#fff}
.btn:disabled{opacity:.5;cursor:default}
.empty{color:#777;text-align:center;margin-top:4rem}
.countdown{font-variant-numeric:tabular-nums;font-weight:600}
.footer{color:#999;font-size:.75rem;margin-top:2rem;text-align:center}
</style>
</head>
<body>
<h1>&#128680; human-gate approval desk</h1>
<p class="meta">Requests from your coding agents appear here. Unanswered requests are
<strong>auto-denied</strong> when their timer runs out.</p>
<div id="list"></div>
<div class="footer">human-gate &mdash; decisions require this private desk URL; agents cannot self-approve.</div>
<script>
const TOKEN = "__TOKEN__";
const BASE = location.pathname.replace(/\\/$/, "");
const headers = {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"};
async function refresh() {
  const r = await fetch(BASE + "/api/requests", {headers});
  const items = await r.json();
  const el = document.getElementById("list");
  if (!items.length) { el.innerHTML = '<div class="empty">No pending requests. Agents are behaving. &#127881;</div>'; return; }
  el.innerHTML = items.map(card).join("");
  items.forEach(i => {
    document.getElementById("a-" + i.id).onclick = () => decide(i.id, true);
    document.getElementById("d-" + i.id).onclick = () => decide(i.id, false);
  });
  tick(items);
}
function card(i) {
  const left = Math.max(0, Math.round(i.expires_at - Date.now() / 1000));
  return `<div class="card">
    <div><span class="risk ${i.risk}">${i.risk}</span> <strong>${esc(i.title)}</strong></div>
    <div class="meta">from <code>${esc(i.agent || "agent")}</code> &middot;
    expires in <span class="countdown" data-exp="${i.expires_at}">${left}s</span></div>
    ${i.detail ? `<div class="detail">${esc(i.detail)}</div>` : ""}
    <button class="btn approve" id="a-${i.id}">Approve</button>
    <button class="btn deny" id="d-${i.id}">Deny</button>
  </div>`;
}
function tick(items) {
  document.querySelectorAll(".countdown").forEach(s => {
    const left = Math.max(0, Math.round(parseFloat(s.dataset.exp) - Date.now() / 1000));
    s.textContent = left + "s";
  });
}
async function decide(id, approve) {
  const note = prompt(approve ? "Optional note for the audit log:" : "Reason (goes to the audit log):", "") || "";
  const r = await fetch(`${BASE}/api/requests/${id}/decision`,
    {method: "POST", headers, body: JSON.stringify({decision: approve ? "approve" : "deny", note})});
  if (!r.ok) alert("Decision failed: " + r.status);
  refresh();
}
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


class GateHandler(BaseHTTPRequestHandler):
    server_version = "human-gate/0.1"

    @property
    def state(self) -> ApprovalState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *args):  # keep test output clean
        pass

    # -- helpers ---------------------------------------------------------
    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _desk_token_from_path(self):
        # returns token string if path is /desk/<token>/..., else None
        parts = urlparse(self.path).path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "desk":
            return parts[1], "/" + "/".join(parts[2:])
        return None, None

    def _bearer_ok(self, token: str) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return self.state.check_token(auth[len("Bearer "):]) and \
            self.state.check_token(token)

    # -- routing ---------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        token, rest = self._desk_token_from_path()
        if token is not None:
            if not self.state.check_token(token):
                self._json({"error": "forbidden"}, 403)
                return
            if rest in ("", "/"):
                page = DESK_HTML.replace("__TOKEN__", self.state.token)
                body = page.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if rest == "/api/requests":
                if not self._bearer_ok(token):
                    self._json({"error": "unauthorized"}, 401)
                    return
                self._json(self.state.list_requests())
                return
            self._json({"error": "not found"}, 404)
            return

        # agent plane (no decision routes exist here by design)
        if path == "/":
            self._json({"service": "human-gate", "version": "0.1.0",
                        "note": "agent API: create requests and poll status. "
                                "Decisions are only possible via the private desk URL."})
            return
        if path == "/api/requests":
            self._json(self.state.list_requests(pending_only=False))
            return
        if path.startswith("/api/requests/"):
            rid = path[len("/api/requests/"):].strip("/")
            req = self.state.get_request(rid)
            if req is None:
                self._json({"error": "not found"}, 404)
                return
            self._json(req)
            return
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        token, rest = self._desk_token_from_path()
        if token is not None:
            if not self.state.check_token(token):
                self._json({"error": "forbidden"}, 403)
                return
            # human plane: decision
            if rest.startswith("/api/requests/") and rest.endswith("/decision"):
                if not self._bearer_ok(token):
                    # tamper attempt: someone reached the desk path without the token
                    self.state.audit.append("decision.rejected",
                                            reason="missing/invalid bearer token",
                                            path=rest[:80])
                    self._json({"error": "unauthorized"}, 401)
                    return
                rid = rest[len("/api/requests/"):-len("/decision")].strip("/")
                data = self._read_json()
                if data is None:
                    self._json({"error": "bad json"}, 400)
                    return
                decision = (data.get("decision") or "").lower()
                if decision not in ("approve", "deny"):
                    self._json({"error": "decision must be approve or deny"}, 400)
                    return
                out = self.state.decide(rid, decision == "approve",
                                        note=data.get("note", ""), via="desk")
                if out is None:
                    self._json({"error": "not found or already decided"}, 409)
                    return
                self._json(out)
                return
            self._json({"error": "not found"}, 404)
            return

        # agent plane
        path = urlparse(self.path).path
        if path == "/api/requests":
            data = self._read_json()
            if data is None:
                self._json({"error": "bad json"}, 400)
                return
            title = (data.get("title") or "").strip()
            if not title:
                self._json({"error": "title is required"}, 400)
                return
            try:
                req = self.state.create_request(
                    title=title,
                    detail=data.get("detail", ""),
                    risk=(data.get("risk") or "medium").lower(),
                    agent=data.get("agent", ""),
                    timeout_secs=data.get("timeout_secs", DEFAULT_TIMEOUT),
                )
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
                return
            self._json({"id": req["id"], "status": req["status"],
                        "expires_at": req["expires_at"]}, 201)
            return
        self._json({"error": "not found"}, 404)


def create_server(port: int, data_dir: str, token: str | None = None) -> ThreadingHTTPServer:
    state = ApprovalState(data_dir, token=token)
    server = ThreadingHTTPServer(("127.0.0.1", port), GateHandler)
    server.state = state  # type: ignore[attr-defined]
    server.daemon_threads = True
    return server


def desk_url(port: int, token: str) -> str:
    digest = hashlib.sha256(token.encode()).hexdigest()[:8]
    return f"http://127.0.0.1:{port}/desk/{token}/  (id {digest})"
