"""CLI for human-gate.

Agent side:  humangate request --title "..." --risk high   (blocks for a decision)
Human side:  humangate serve                              (prints the private desk URL)
             humangate decide --id <id> --approve --token <token>
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

from . import __version__
from .audit import AuditLog
from .server import DEFAULT_TIMEOUT, create_server, desk_url

DEFAULT_SERVER = os.environ.get("HUMAN_GATE_SERVER", "http://127.0.0.1:8765")
DEFAULT_DATA_DIR = os.environ.get("HUMAN_GATE_DATA_DIR",
                                  os.path.expanduser("~/.humangate"))


def _api(server: str, method: str, path: str, data=None, headers=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(server + path, data=body, method=method,
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode() or "{}")
        except Exception:
            detail = {"error": f"http {exc.code}"}
        return exc.code, detail
    except OSError as exc:
        print(f"error: cannot reach human-gate server at {server}: {exc}",
              file=sys.stderr)
        sys.exit(2)


def cmd_serve(args) -> int:
    server = create_server(args.port, args.data_dir)
    token = server.state.token  # type: ignore[attr-defined]
    url = desk_url(server.socket.getsockname()[1], token)
    print("=" * 70)
    print("human-gate approval desk is running.")
    print()
    print("  Open this private URL in YOUR browser (do NOT share it with agents):")
    print(f"  {url}")
    print()
    print("  The agent API is on http://127.0.0.1:%d/ (create + poll only)." %
          server.socket.getsockname()[1])
    print("  Agents cannot approve their own requests: there is no decision")
    print("  endpoint outside the private desk URL.")
    print("=" * 70, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nhuman-gate stopped.")
    return 0


def cmd_request(args) -> int:
    status, created = _api(args.server, "POST", "/api/requests", {
        "title": args.title,
        "detail": args.detail or "",
        "risk": args.risk,
        "agent": args.agent or "",
        "timeout_secs": args.timeout,
    })
    if status not in (200, 201):
        print(f"error: request rejected: {created}", file=sys.stderr)
        return 2
    rid = created["id"]
    print(f"approval requested: id={rid} (waiting up to {args.timeout}s, "
          f"default-deny on timeout)", flush=True)
    deadline = time.time() + args.timeout + 5
    while time.time() < deadline:
        time.sleep(args.poll_interval)
        status, req = _api(args.server, "GET", f"/api/requests/{rid}")
        if status != 200:
            continue
        if req["status"] != "pending":
            if req["status"] == "approved":
                print(f"APPROVED via {req['decided_via']}"
                      + (f": {req['decision_note']}" if req.get("decision_note") else ""))
                return 0
            via = req.get("decided_via") or "unknown"
            print(f"DENIED (via {via})"
                  + (f": {req['decision_note']}" if req.get("decision_note") else ""))
            return 1
    print("DENIED (timed out waiting for the desk; default-deny)")
    return 1


def cmd_status(args) -> int:
    status, req = _api(args.server, "GET", f"/api/requests/{args.id}")
    if status != 200:
        print(f"error: {req}", file=sys.stderr)
        return 1
    print(json.dumps(req, indent=2, ensure_ascii=False))
    return 0


def cmd_decide(args) -> int:
    # Human-side terminal approval. Requires the desk token (shown only in the
    # terminal where `humangate serve` runs) — agents never have it.
    if not args.token:
        print("error: --token is required (find it in the `humangate serve` output)",
              file=sys.stderr)
        return 2
    decision = "approve" if args.approve else "deny"
    status, out = _api(
        args.server, "POST",
        f"/desk/{args.token}/api/requests/{args.id}/decision",
        {"decision": decision, "note": args.note or ""},
        headers={"Authorization": f"Bearer {args.token}"},
    )
    if status != 200:
        print(f"error: decision rejected: {out}", file=sys.stderr)
        return 1
    word = "APPROVED" if decision == "approve" else "DENIED"
    print(f"{word}: {out['id']} ({out['status']})")
    return 0


def cmd_audit_verify(args) -> int:
    ok, msg = AuditLog(os.path.join(args.data_dir, "audit.jsonl")).verify()
    print(msg)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="humangate",
                                description="Human approval channel for coding agents.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="start the approval daemon + desk")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    s.set_defaults(func=cmd_serve)

    r = sub.add_parser("request", help="ask the human for approval (blocks)")
    r.add_argument("--title", required=True, help="short summary of what needs approval")
    r.add_argument("--detail", default="", help="details shown on the desk")
    r.add_argument("--risk", default="medium", choices=["low", "medium", "high", "critical"])
    r.add_argument("--agent", default="", help="agent name shown on the desk")
    r.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help="seconds before default-deny (default 300)")
    r.add_argument("--poll-interval", type=float, default=2.0)
    r.add_argument("--server", default=DEFAULT_SERVER)
    r.set_defaults(func=cmd_request)

    t = sub.add_parser("status", help="check a request's status")
    t.add_argument("--id", required=True)
    t.add_argument("--server", default=DEFAULT_SERVER)
    t.set_defaults(func=cmd_status)

    d = sub.add_parser("decide", help="human terminal approval (needs desk token)")
    d.add_argument("--id", required=True)
    d.add_argument("--approve", action="store_true")
    d.add_argument("--deny", action="store_true")
    d.add_argument("--note", default="")
    d.add_argument("--token", default="", help="desk token from `humangate serve` output")
    d.add_argument("--server", default=DEFAULT_SERVER)
    d.set_defaults(func=cmd_decide)

    v = sub.add_parser("audit-verify", help="verify the audit log hash chain")
    v.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    v.set_defaults(func=cmd_audit_verify)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "cmd", None) == "decide" and not (args.approve ^ args.deny):
        print("error: decide needs exactly one of --approve / --deny", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
