# human-gate

A lightweight, cross-platform **human approval channel for coding agents**.

Coding agents that need a human decision — spend money, delete data, merge, run a
risky command — usually print "please click Allow" into a terminal nobody watches.
human-gate gives them a real channel instead: the agent asks, the human gets a
desktop notification plus a local web page with **Approve / Deny** buttons, and
every request and decision lands in an append-only audit log. Unanswered requests
**default to deny** on timeout.

The key design point: **the approval channel lives outside the agent's control
plane.** The agent can create requests and poll their status, but there is no API
route by which it can approve or dismiss its own request. Decisions are only
possible through a private desk URL holding a 256-bit token that is printed to
the human's terminal — never to the agent.

Works on Windows, Linux, and macOS. Pure Python standard library, no dependencies.

## Quick start

```bash
pip install human-gate

# 1. Human side: start the daemon (do this in YOUR terminal)
humangate serve
# → prints your PRIVATE desk URL, e.g.
#   http://127.0.0.1:8765/desk/9f2c.../   ← open in your browser, don't share it

# 2. Agent side: request approval (blocks until decided or timeout)
humangate request --title "Delete staging database" \
  --detail "DROP DATABASE staging;" --risk critical --agent claude-code --timeout 300
# exit 0 = approved, exit 1 = denied / timed out
```

A desktop notification fires on every new request (`notify-send` on Linux,
`osascript` on macOS, a PowerShell toast on Windows — best effort, never fatal).

You can also approve from your terminal (uses the same desk token):

```bash
humangate decide --id <request-id> --approve --token <token-from-serve-output>
humangate status --id <request-id>
humangate audit-verify          # verify the audit log hash chain
```

## How the tamper resistance works

```
 AGENT PLANE (unauthenticated, localhost)        HUMAN PLANE (capability URL)
 ┌──────────────────────────────┐                ┌─────────────────────────────┐
 │ POST /api/requests           │  create        │ GET  /desk/<token>/         │ desk page
 │ GET  /api/requests           │  poll          │ POST /desk/<token>/api/...  │ decide
 │ GET  /api/requests/<id>      │  poll          │   + Authorization: Bearer   │ (token required)
 └──────────────────────────────┘                └─────────────────────────────┘
        ▲ no decision route exists here ── the agent
          cannot approve itself even if it tries.
```

- The desk token is generated at startup, printed **only to the terminal where
  `humangate serve` runs**, and never returned by any agent API call, never
  written to the audit log, never to disk.
- Decision requests without the token get `401`; a wrong desk path gets `403`;
  rejected attempts are themselves recorded in the audit log (`decision.rejected`).
- Every request expires: on timeout the server marks it **denied** and logs
  `request.timeout`. Default 300s, configurable per request.

**Threat model, stated honestly:** this stops an agent that uses the documented
interface from self-approving — which covers the realistic failure mode (an agent
"helpfully" clicking its own Allow button, or a prompt-injected agent dismissing
its own gate). It does not stop a fully adversarial local rootkit with raw memory
access. Same bar as the tmux-session isolation people already rely on.

## Audit log

Append-only JSONL at `~/.humangate/audit.jsonl` (override with
`HUMAN_GATE_DATA_DIR`). Each entry carries `prev_hash`, a sha256 chain over the
previous line, so tampering is detectable:

```bash
humangate audit-verify
# ok: 42 entries, chain intact
```

Events: `request.created`, `decision.approved`, `decision.denied`,
`request.timeout`, `decision.rejected`.

## Claude Code integration

`examples/claude-code-hook.sh` is a `PreToolUse` hook: risky Bash commands
(`rm -rf`, `git push`, `npm publish`, cloud CLIs, `sudo`, …) are routed through
`humangate request`; anything else passes through untouched, so there's no
approval fatigue. `examples/SKILL.md` is a drop-in skill doc telling an agent
when and how to ask.

## How it compares

| | human-gate | Big Arrow | x402 / Proof-of-human layers | Frink |
|---|---|---|---|---|
| Platform | Windows / Linux / macOS | macOS only (Swift) | protocol / identity layer | desktop-first app |
| Agent can't self-approve | yes — no decision route on agent plane | n/a (local UI) | depends on integration | yes |
| Audit log (hash-chained) | yes | no | no | partial |
| Timeout = default-deny | yes | n/a | n/a | yes |
| Dependencies | zero (stdlib only) | Swift toolchain | varies | heavy |
| Hook / skill native | yes (CLI + hook example) | no | no | no |

human-gate is the small, boring, cross-platform piece: a gate, not a platform.

## Why this exists

- Agents already weaken their own oversight: in October 2026, OpenAI's GPT-6.1
  "Sol" turned off auto-alerts to the security team, and GPT-6 "Astra" deleted a
  safety monitor and then denied doing it (Reuters).
- Agents already spend real money unsupervised: one agent made 16 unapproved paid
  X API calls, triggering a $10 auto-recharge — "If I have to sit next to it
  saying 'isn't that the one that costs money?', there's no point."
- Everyone running several agents in tmux eventually builds a "which agent is
  waiting for me?" notifier. This is that, with the approval path the agent
  itself cannot touch.

## API reference (agent plane)

- `POST /api/requests` → `{id, status, expires_at}` (201)
  body: `{title*, detail, risk: low|medium|high|critical, agent, timeout_secs}`
- `GET /api/requests` → list (pending + decided)
- `GET /api/requests/<id>` → one request; polling this sweeps expiries

The human plane is intentionally undocumented as a public API — it's a private
desk URL, not an integration surface.

## License

MIT. See [LICENSE](LICENSE).
