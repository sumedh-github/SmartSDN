#!/usr/bin/env bash
set -euo pipefail

# Capture live "mininet> net" output from an existing tmux Mininet session.
# Intended to be used by backend discovery via:
#   export SOC_MININET_NET_CMD="/abs/path/to/Project/scripts/mininet_net_dump.sh"

SESSION_NAME="${MININET_TMUX_SESSION:-mn}"
PANE_TARGET="${MININET_TMUX_PANE:-0.0}"
CAPTURE_LINES="${MININET_CAPTURE_LINES:-300}"
WAIT_SECONDS="${MININET_DUMP_WAIT_SECONDS:-4}"

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required but not found in PATH." >&2
  exit 1
fi

if ! tmux has-session -t "=${SESSION_NAME}" 2>/dev/null; then
  echo "tmux session '${SESSION_NAME}' was not found." >&2
  echo "Start Mininet inside tmux first, for example:" >&2
  echo "  tmux new -s ${SESSION_NAME}" >&2
  echo "  sudo mn --topo single,3 --mac --switch ovsk,protocols=OpenFlow13 --controller remote" >&2
  exit 1
fi

MARKER="__MININET_NET_DUMP_DONE_$(date +%s%N)__"
TARGET="${SESSION_NAME}:${PANE_TARGET}"

tmux send-keys -t "${TARGET}" "net" C-m
tmux send-keys -t "${TARGET}" "echo ${MARKER}" C-m

deadline=$((SECONDS + WAIT_SECONDS))
while ((SECONDS <= deadline)); do
  pane_text="$(tmux capture-pane -p -t "${TARGET}" -S "-${CAPTURE_LINES}" || true)"
  if [[ "${pane_text}" == *"${MARKER}"* ]]; then
    printf "%s\n" "${pane_text}" | awk -v marker="${MARKER}" '
      {
        lines[NR] = $0
      }
      /^[[:space:]]*mininet>[[:space:]]+net[[:space:]]*$/ {
        net_start = NR
      }
      index($0, marker) > 0 {
        marker_line = NR
      }
      END {
        if (!net_start || !marker_line || marker_line <= net_start) {
          exit 1
        }
        for (i = net_start + 1; i < marker_line; i++) {
          if (lines[i] ~ /^[[:space:]]*mininet>/) {
            continue
          }
          print lines[i]
        }
      }
    '
    exit 0
  fi
  sleep 0.15
done

echo "Timed out waiting for Mininet net output marker." >&2
exit 1
