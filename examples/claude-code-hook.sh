#!/usr/bin/env bash
# Claude Code PreToolUse hook example: route risky tool calls through human-gate.
#
# Install: copy into your project's .claude/settings.json hooks, e.g.
#   {
#     "hooks": {
#       "PreToolUse": [
#         { "matcher": "Bash", "hooks": [{ "type": "command", "command": "path/to/claude-code-hook.sh" }] }
#       ]
#     }
#   }
#
# The hook receives the tool call as JSON on stdin. If the command looks risky,
# it asks the human via `humangate request` and blocks until approved/denied.
# Exit 0 = allow the tool call, exit 2 = block it (Claude Code hook convention).
set -euo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tool_name',''))")
COMMAND=$(echo "$INPUT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tool_input',{}).get('command',''))")

# Only gate Bash; extend the case list for Edit/Write/etc. as you like.
[ "$TOOL" = "Bash" ] || exit 0

RISKY='rm -rf|mkfs|dd |shutdown|reboot|git push|npm publish|twine upload|aws |gcloud |az |kubectl delete|pip install|sudo '
if echo "$COMMAND" | grep -Eq "$RISKY"; then
  RISK="high"
else
  # Non-risky commands pass straight through — no approval fatigue.
  exit 0
fi

if humangate request \
    --title "Bash: ${COMMAND:0:120}" \
    --detail "Full command:\n$COMMAND" \
    --risk "$RISK" \
    --agent "claude-code" \
    --timeout 300; then
  echo "human-gate: approved by human" >&2
  exit 0
else
  echo "human-gate: denied or timed out — blocking tool call" >&2
  exit 2
fi
