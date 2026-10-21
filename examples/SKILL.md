# SKILL.md — human-gate agent skill

Use human-gate whenever you are about to do something a human should sign off on:
spending money, deleting or overwriting data, publishing, merging, running
destructive shell commands, or touching production.

## Setup (once per machine)

```bash
pip install human-gate
humangate serve   # prints your PRIVATE desk URL — open it in your browser
```

Keep `humangate serve` running in a terminal you can see. Leave the desk page open.

## Requesting approval (agent side)

```bash
humangate request \
  --title "Delete staging database" \
  --detail "DROP DATABASE staging; requested by deploy script v2.3" \
  --risk critical \
  --agent "claude-code" \
  --timeout 300
```

- Exit code `0` = human approved. Anything else = denied (or timed out).
- `--risk` is one of `low | medium | high | critical`.
- Timeout defaults to 300s and **always defaults to deny**.
- A desktop notification fires on the human's machine for every request.

Do NOT proceed on a non-zero exit. Do not retry the same request in a loop —
if the human denied it, accept the decision.

## Rules

1. Never try to approve your own request. The desk URL and its token are the
   human's; the agent API has no decision endpoint at all.
2. Batch related approvals into one request instead of spamming many.
3. Put the real command / diff / cost in `--detail` so the human can judge.
4. Low-risk read-only work never needs approval — don't create approval fatigue.
