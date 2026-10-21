"""Tests for human-gate. Localhost only; no external network."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from unittest import mock

from humangate import cli
from humangate.audit import AuditLog
from humangate.notifier import notify
from humangate.server import create_server

TOKEN = "test-token-" + "a" * 40


def raw(server_url, method, path, data=None, headers=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(server_url + path, data=body, method=method,
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


class GateTestCase(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="humangate-test-")
        self.server = create_server(0, self.data_dir, token=TOKEN)
        self.port = self.server.socket.getsockname()[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.state = self.server.state
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.bearer = {"Authorization": f"Bearer {TOKEN}"}
        self.desk = f"/desk/{TOKEN}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def create(self, **kw):
        data = {"title": "do the thing", "risk": "high", "agent": "test-agent"}
        data.update(kw)
        status, body = raw(self.base, "POST", "/api/requests", data)
        self.assertIn(status, (200, 201), body)
        return json.loads(body)

    def decide(self, rid, approve=True, headers=None, token_path=TOKEN):
        return raw(self.base, "POST",
                   f"/desk/{token_path}/api/requests/{rid}/decision",
                   {"decision": "approve" if approve else "deny", "note": "test"},
                   headers if headers is not None else self.bearer)

    def get_req(self, rid):
        status, body = raw(self.base, "GET", f"/api/requests/{rid}")
        self.assertEqual(status, 200, body)
        return json.loads(body)

    # -- agent plane ------------------------------------------------------
    def test_create_and_poll(self):
        created = self.create(title="rm -rf /tmp/cache", detail="cleanup")
        self.assertEqual(created["status"], "pending")
        req = self.get_req(created["id"])
        self.assertEqual(req["title"], "rm -rf /tmp/cache")
        self.assertEqual(req["risk"], "high")

    def test_create_validation(self):
        status, _ = raw(self.base, "POST", "/api/requests", {"title": ""})
        self.assertEqual(status, 400)
        status, _ = raw(self.base, "POST", "/api/requests",
                        {"title": "x", "risk": "extreme"})
        self.assertEqual(status, 400)

    def test_agent_plane_has_no_decision_route(self):
        # The whole point: nothing on the agent plane can decide.
        for path in ("/api/decide", "/api/requests/abc123/decision",
                     "/api/requests/abc123/approve"):
            status, _ = raw(self.base, "POST", path, {"decision": "approve"})
            self.assertEqual(status, 404, path)

    def test_agent_api_never_leaks_token(self):
        self.create()
        status, body = raw(self.base, "GET", "/api/requests")
        self.assertEqual(status, 200)
        self.assertNotIn(TOKEN, body)
        with open(os.path.join(self.data_dir, "audit.jsonl")) as fh:
            self.assertNotIn(TOKEN, fh.read())

    # -- human plane ------------------------------------------------------
    def test_approve_with_token(self):
        created = self.create()
        status, body = self.decide(created["id"], approve=True)
        self.assertEqual(status, 200, body)
        req = self.get_req(created["id"])
        self.assertEqual(req["status"], "approved")
        self.assertEqual(req["decided_via"], "desk")

    def test_deny_with_token(self):
        created = self.create()
        status, _ = self.decide(created["id"], approve=False)
        self.assertEqual(status, 200)
        self.assertEqual(self.get_req(created["id"])["status"], "denied")

    def test_decide_without_bearer_is_rejected(self):
        created = self.create()
        status, _ = self.decide(created["id"], headers={})
        self.assertEqual(status, 401)
        self.assertEqual(self.get_req(created["id"])["status"], "pending")

    def test_decide_with_wrong_bearer_is_rejected(self):
        created = self.create()
        status, _ = self.decide(created["id"],
                                headers={"Authorization": "Bearer wrong"})
        self.assertEqual(status, 401)
        self.assertEqual(self.get_req(created["id"])["status"], "pending")

    def test_wrong_desk_path_is_forbidden(self):
        created = self.create()
        status, _ = self.decide(created["id"], token_path="wrong-token")
        self.assertEqual(status, 403)
        self.assertEqual(self.get_req(created["id"])["status"], "pending")

    def test_desk_page_requires_token(self):
        status, body = raw(self.base, "GET", f"/desk/{TOKEN}/")
        self.assertEqual(status, 200)
        self.assertIn("approval desk", body)
        status, _ = raw(self.base, "GET", "/desk/nope/")
        self.assertEqual(status, 403)

    def test_double_decide_rejected(self):
        created = self.create()
        status, _ = self.decide(created["id"], approve=True)
        self.assertEqual(status, 200)
        status, _ = self.decide(created["id"], approve=False)
        self.assertEqual(status, 409)
        self.assertEqual(self.get_req(created["id"])["status"], "approved")

    def test_decide_unknown_id(self):
        status, _ = self.decide("doesnotexist", headers=self.bearer)
        self.assertEqual(status, 409)

    # -- timeout = default-deny --------------------------------------------
    def test_timeout_auto_denies(self):
        created = self.create(title="slow human", timeout_secs=1)
        time.sleep(1.3)
        req = self.get_req(created["id"])
        self.assertEqual(req["status"], "denied")
        self.assertEqual(req["decided_via"], "timeout")

    def test_cannot_decide_after_timeout(self):
        created = self.create(timeout_secs=1)
        time.sleep(1.3)
        status, _ = self.decide(created["id"], approve=True)
        self.assertEqual(status, 409)
        self.assertEqual(self.get_req(created["id"])["status"], "denied")

    # -- audit log ---------------------------------------------------------
    def test_audit_chain_verifies(self):
        created = self.create(title="audit me")
        self.decide(created["id"], approve=True)
        self.create(title="timeout me", timeout_secs=1)
        time.sleep(1.3)
        raw(self.base, "GET", "/api/requests")  # poll sweeps expiries
        log = AuditLog(os.path.join(self.data_dir, "audit.jsonl"))
        ok, msg = log.verify()
        self.assertTrue(ok, msg)
        events = [e["event"] for e in log.entries()]
        self.assertIn("request.created", events)
        self.assertIn("decision.approved", events)
        self.assertIn("request.timeout", events)

    def test_audit_tamper_detected(self):
        self.create(title="tamper me")
        path = os.path.join(self.data_dir, "audit.jsonl")
        log = AuditLog(path)
        ok, _ = log.verify()
        self.assertTrue(ok)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write('{"event": "decision.approved", "forged": true}\n')
        ok, msg = AuditLog(path).verify()
        self.assertFalse(ok)
        self.assertIn("chain broken", msg)

    # -- CLI ---------------------------------------------------------------
    def test_cli_request_approved(self):
        server_arg = ["--server", self.base]
        result = {}

        def decide_soon():
            time.sleep(0.4)
            reqs = self.state.list_requests()
            rid = [r["id"] for r in reqs if r["status"] == "pending"][-1]
            self.state.decide(rid, True, note="cli test", via="desk")

        threading.Thread(target=decide_soon, daemon=True).start()
        rc = cli.main(["request", "--title", "cli approval test",
                       "--timeout", "10", "--poll-interval", "0.2"] + server_arg)
        self.assertEqual(rc, 0)

    def test_cli_request_timeout_denies(self):
        rc = cli.main(["request", "--title", "nobody home",
                       "--timeout", "1", "--poll-interval", "0.2",
                       "--server", self.base])
        self.assertEqual(rc, 1)

    def test_cli_decide_needs_token(self):
        rc = cli.main(["decide", "--id", "abc", "--approve", "--server", self.base])
        self.assertEqual(rc, 2)

    def test_cli_decide_with_token(self):
        created = self.create(title="terminal approval")
        rc = cli.main(["decide", "--id", created["id"], "--deny",
                       "--token", TOKEN, "--note", "nope",
                       "--server", self.base])
        self.assertEqual(rc, 0)
        self.assertEqual(self.get_req(created["id"])["status"], "denied")

    def test_cli_decide_wrong_token(self):
        created = self.create(title="terminal approval 2")
        rc = cli.main(["decide", "--id", created["id"], "--approve",
                       "--token", "wrong", "--server", self.base])
        self.assertEqual(rc, 1)
        self.assertEqual(self.get_req(created["id"])["status"], "pending")

    def test_cli_audit_verify(self):
        self.create()
        rc = cli.main(["audit-verify", "--data-dir", self.data_dir])
        self.assertEqual(rc, 0)

    # -- notifier never raises ----------------------------------------------
    def test_notifier_never_raises(self):
        with mock.patch("humangate.notifier.subprocess.run",
                        side_effect=OSError("nope")):
            for system in ("Darwin", "Windows", "Linux"):
                with mock.patch("humangate.notifier.platform.system",
                                return_value=system):
                    self.assertFalse(notify("t", "b"))

    def test_notifier_uses_notify_send_on_linux(self):
        with mock.patch("humangate.notifier.platform.system", return_value="Linux"), \
             mock.patch("humangate.notifier.shutil.which", return_value="/usr/bin/notify-send"), \
             mock.patch("humangate.notifier.subprocess.run") as run:
            self.assertTrue(notify("t", "b"))
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
