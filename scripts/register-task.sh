#!/usr/bin/env bash
# Register the nightly scrub as a Windows scheduled task.
#
# schtasks is a native Windows tool, so this is the one place a bash script has
# to shell out to cmd.  Native tools must be called as `cmd.exe /c "..."` here:
# MSYS eats a leading `//` in an argument, so `schtasks //Create` arrives as
# `/Create` and fails.
#
#   ./scripts/register-task.sh            register or update, 00:00 daily
#   ./scripts/register-task.sh --remove   delete the task
#   ./scripts/register-task.sh --run      run it once now, out of schedule
#   ./scripts/register-task.sh --status   show whether it exists
set -euo pipefail

TASK_NAME="${IPSCRUB_TASK_NAME:-ipscrub-nightly}"
REPO="${IPSCRUB_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
SCRIPT="$REPO/scripts/nightly.sh"
BASH_EXE="${IPSCRUB_BASH:-C:/Program Files/Git/bin/bash.exe}"

# The machine-specific values live here, not in nightly.sh, so the committed
# script stays generic.  Override any of them from the environment.
INSTANCE="${IPSCRUB_INSTANCE:?set IPSCRUB_INSTANCE to the EC2 instance to clean}"
REGION="${IPSCRUB_REGION:-ap-northeast-1}"
PROFILE="${IPSCRUB_PROFILE:-default}"
PYTHON="${IPSCRUB_PYTHON:-python3}"
AWS_BIN="${IPSCRUB_AWS:-aws}"
TIMEOUT="${IPSCRUB_TIMEOUT:-2700}"

# schtasks wants a Windows path and a quoted command line.
win() { cygpath -w "$1"; }

action="${1:---register}"

case "$action" in
  --remove)
    cmd.exe /c "schtasks /Delete /TN \"$TASK_NAME\" /F"
    echo "removed task: $TASK_NAME"
    exit 0
    ;;
  --status)
    cmd.exe /c "schtasks /Query /TN \"$TASK_NAME\" /V /FO LIST" 2>/dev/null \
      || { echo "task not registered: $TASK_NAME"; exit 1; }
    exit 0
    ;;
  --run)
    cmd.exe /c "schtasks /Run /TN \"$TASK_NAME\""
    echo "started task: $TASK_NAME (report lands in $REPO/state/latest.txt)"
    exit 0
    ;;
  --register) ;;
  *)
    echo "usage: $0 [--register|--remove|--run|--status]" >&2
    exit 2
    ;;
esac

test -f "$SCRIPT" || { echo "missing $SCRIPT" >&2; exit 2; }
test -f "$BASH_EXE" || { echo "missing bash: $BASH_EXE" >&2; exit 2; }

# /TR is one command line: the interpreter, then the script.
#
# schtasks parses /TR itself and a value containing spaces needs its own outer
# quotes, which then have to survive cmd and bash.  Borrowing the usual trick:
# run bash with a path that has no spaces by pointing at the 8.3 form first,
# and fall back to quoting if the volume has 8.3 names disabled.
BASH_SHORT="$(cygpath -d "$BASH_EXE" 2>/dev/null || true)"
if [ -n "$BASH_SHORT" ] && [ -f "$BASH_SHORT" ]; then
  TR_VALUE="$(win "$BASH_SHORT") $(win "$SCRIPT")"
else
  TR_VALUE="\\\"$(win "$BASH_EXE")\\\" \\\"$(win "$SCRIPT")\\\""
fi

# schtasks records only the command line, so variables exported here would not
# be inherited by the task at run time.  The machine-specific values are written
# to a local env file instead, which nightly.sh sources.  It lives under state/,
# which is gitignored, so the account never reaches the repository.
mkdir -p "$REPO/state"
ENV_FILE="$REPO/state/nightly.env"
{
  echo "# Written by scripts/register-task.sh; sourced by scripts/nightly.sh."
  echo "IPSCRUB_INSTANCE=$INSTANCE"
  echo "IPSCRUB_REGION=$REGION"
  echo "IPSCRUB_PROFILE=$PROFILE"
  echo "IPSCRUB_PYTHON=$PYTHON"
  echo "IPSCRUB_AWS=$AWS_BIN"
  echo "IPSCRUB_TIMEOUT=$TIMEOUT"
  echo "IPSCRUB_REPO=$(win "$REPO")"
} >"$ENV_FILE"
chmod 600 "$ENV_FILE" 2>/dev/null || true

BAT="$(mktemp -d)/register.bat"
cat >"$BAT" <<BATEOF
@echo off
schtasks /Create /TN "${TASK_NAME}" /TR "${TR_VALUE}" /SC DAILY /ST 00:00 /F
BATEOF
cmd.exe /c "$(win "$BAT")"
rm -f "$BAT"

echo "registered: $TASK_NAME"
echo "  schedule: daily 00:00 (local time)"
echo "  command : $TR_VALUE"
echo "  report  : $REPO/state/latest.txt"
echo
echo "check it: $0 --status"
echo "run now : $0 --run"
