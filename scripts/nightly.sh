#!/usr/bin/env bash
# Nightly address scrub for the development host.
#
# Runs from Windows Task Scheduler, so it must not assume an interactive shell:
# PATH is minimal, there is no console, and a hang is invisible.  Everything that
# can fail loudly writes to the same log the report goes to.
#
# Exit codes match the CLI: 0 clean, 1 residual matches left, 2 something broke.
#
# Set IPSCRUB_NO_POPUP=1 to skip the desktop notification (handy when testing).
set -uo pipefail

REPO="${IPSCRUB_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"

# Machine-specific values (instance id, profile, interpreter paths) live in a
# gitignored env file so this script stays generic.  Written by register-task.sh.
if [ -f "$REPO/state/nightly.env" ]; then
  # shellcheck disable=SC1090,SC1091
  . "$REPO/state/nightly.env"
fi

PYTHON="${IPSCRUB_PYTHON:-python3}"
AWS="${IPSCRUB_AWS:-aws}"
STATE="${IPSCRUB_STATE:-$REPO/state}"
INSTANCE="${IPSCRUB_INSTANCE:?set IPSCRUB_INSTANCE, or run scripts/register-task.sh first}"
REGION="${IPSCRUB_REGION:-ap-northeast-1}"
PROFILE="${IPSCRUB_PROFILE:-default}"
# A real pass over dev-west reads ~3.5 GB and measured 14m29s.  The AWS client
# default of 600s cuts that off mid-run and leaves the remote process burning
# CPU, so the budget here is deliberately generous.
TIMEOUT="${IPSCRUB_TIMEOUT:-2700}"

WSCRIPT="${WINDIR:-C:/Windows}/System32/wscript.exe"
export IPSCRUB_AWS="$AWS"
export PYTHONPATH="$REPO/src"
export PYTHONIOENCODING=utf-8

mkdir -p "$STATE"
REPORT="$STATE/latest.txt"
LOG="$STATE/run.log"

echo "=== $(date -u '+%Y-%m-%d %H:%M:%S') UTC ===" >>"$LOG"

"$PYTHON" -m ipscrub nightly --region "$REGION" --profile "$PROFILE" --instance "$INSTANCE" --state-dir "$STATE" --keep 5 --timeout "$TIMEOUT" 2>&1 | tee -a "$LOG"
STATUS="${PIPESTATUS[0]}"

# The headline is what the notification shows, so read it back rather than
# rebuilding it: one source of truth for the numbers.
if [ -f "$REPORT" ]; then
  HEADLINE="$(head -1 "$REPORT")"
else
  HEADLINE="ipscrub nightly failed, see $LOG"
fi

case "$STATUS" in
  0) TITLE="ipscrub: clean" ;;
  1) TITLE="ipscrub: matches left" ;;
  *) TITLE="ipscrub: FAILED" ;;
esac

if [ "${IPSCRUB_NO_POPUP:-0}" != "1" ] && [ -x "$WSCRIPT" ]; then
  # Best effort only: a toast that cannot be shown must never change the verdict.
  # Popup is modal for its timeout, so it is launched detached.
  {
    printf 'Set shell = CreateObject("WScript.Shell")\n'
    printf 'shell.Popup "%s", 20, "%s", 64\n' "${HEADLINE//\"/}" "${TITLE//\"/}"
  } >"$STATE/notify.vbs"
  "$WSCRIPT" //nologo "$(cygpath -w "$STATE/notify.vbs")" >/dev/null 2>&1 &
fi

exit "$STATUS"
