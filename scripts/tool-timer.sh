#!/usr/bin/env bash
# Kestrel tool-timer.sh — wraps a command, recording tool_start/tool_end events
# in sessions.jsonl with wall-clock duration_s.
#
# Usage: tool-timer.sh --session-dir <DIR> --tool <name> -- <cmd...>
#
# The '--' separator is required between flags and the command to run.
# stdout and stderr of <cmd> are forwarded unchanged (the session-dir
# creation is the only side-effect on the filesystem before cmd runs).
# The script exits with the same exit code as the wrapped command.

SESSION_DIR=""
TOOL_NAME=""

while [[ $# -gt 0 && "$1" != "--" ]]; do
    case "$1" in
        --session-dir) SESSION_DIR="$2"; shift 2 ;;
        --tool)        TOOL_NAME="$2";   shift 2 ;;
        *)
            echo "tool-timer: unknown flag: $1" >&2
            exit 1
            ;;
    esac
done
[[ "$1" == "--" ]] && shift   # consume the separator

if [[ -z "$SESSION_DIR" || -z "$TOOL_NAME" || $# -eq 0 ]]; then
    echo "Usage: tool-timer.sh --session-dir <DIR> --tool <name> -- <cmd...>" >&2
    exit 1
fi

JSONL="$SESSION_DIR/sessions.jsonl"
mkdir -p "$SESSION_DIR"

_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_epoch() { date +%s; }

_stamp() { printf '%s\n' "$1" >> "$JSONL"; }

TS_START=$(_ts)
T_START=$(_epoch)
_stamp "{\"ts\":\"$TS_START\",\"phase\":\"tool-timer\",\"event\":\"tool_start\",\"detail\":\"$TOOL_NAME\"}"

EXIT_CODE=0
"$@" || EXIT_CODE=$?

T_END=$(_epoch)
TS_END=$(_ts)
DURATION_S=$(( T_END - T_START ))

_stamp "{\"ts\":\"$TS_END\",\"phase\":\"tool-timer\",\"event\":\"tool_end\",\"detail\":\"$TOOL_NAME\",\"duration_s\":$DURATION_S,\"exit_code\":$EXIT_CODE}"

exit $EXIT_CODE
