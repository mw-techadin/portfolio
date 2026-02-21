#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# linux_audit.sh
# Audits local user accounts, sudo privileges, and last login times.
# Raises an alert if unexpected users with login shells are found.
#
# Usage:
#   ./linux_audit.sh
#   ./linux_audit.sh --whitelist "alice,bob,deploy"
#   ./linux_audit.sh --output /var/log/audit_report.txt
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
WHITELIST="${WHITELIST:-root}"     # comma-separated expected users
OUTPUT_FILE=""
ALERT_EMAIL=""
DIVIDER="$(printf '=%.0s' {1..60})"

# ── Argument parsing ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --whitelist) WHITELIST="$2";    shift 2 ;;
    --output)    OUTPUT_FILE="$2";  shift 2 ;;
    --email)     ALERT_EMAIL="$2";  shift 2 ;;
    *) echo "[WARN] Unknown argument: $1"; shift ;;
  esac
done

# ── Helper functions ───────────────────────────────────────────────────────────
log() {
  if [[ -n "$OUTPUT_FILE" ]]; then
    echo "$*" | tee -a "$OUTPUT_FILE"
  else
    echo "$*"
  fi
}

timestamp() {
  date "+%Y-%m-%d %H:%M:%S"
}

# ── Build whitelist set ────────────────────────────────────────────────────────
declare -A ALLOWED_USERS
IFS=',' read -ra WL <<< "$WHITELIST"
for user in "${WL[@]}"; do
  ALLOWED_USERS["$(echo "$user" | tr -d ' ')"]=1
done

# ── Clear/init output file ─────────────────────────────────────────────────────
if [[ -n "$OUTPUT_FILE" ]]; then
  > "$OUTPUT_FILE"
fi

ALERT_COUNT=0

# ─────────────────────────────────────────────────────────────────────────────
log "$DIVIDER"
log "  Linux User Audit Report  |  $(timestamp)"
log "$DIVIDER"

# ── Section 1: Users with login shells ────────────────────────────────────────
log ""
log "  [1] Users with interactive login shells"
log "  $(printf -- '-%.0s' {1..58})"

while IFS=: read -r username _ uid gid _ home shell; do
  # Skip system accounts (UID < 1000) except root
  if [[ "$uid" -lt 1000 && "$username" != "root" ]]; then
    continue
  fi
  # Skip nologin / false shells
  if [[ "$shell" == */nologin || "$shell" == */false ]]; then
    continue
  fi

  status="OK"
  if [[ -z "${ALLOWED_USERS[$username]+_}" ]]; then
    status="UNEXPECTED"
    (( ALERT_COUNT++ )) || true
  fi

  last_login="$(lastlog -u "$username" 2>/dev/null | tail -1 | awk '{print $4,$5,$6,$7,$8}' || echo 'unknown')"

  log "  $(printf '%-16s' "$username")  uid=$uid  shell=$shell"
  log "    Last login : ${last_login:-never}"
  log "    Status     : $status"
  log ""
done < /etc/passwd

# ── Section 2: Sudo privileges ────────────────────────────────────────────────
log "  [2] Users with sudo access"
log "  $(printf -- '-%.0s' {1..58})"

if [[ -f /etc/sudoers ]]; then
  # Direct sudoers entries (non-comment, non-default, non-include lines)
  grep -v '^\s*#' /etc/sudoers 2>/dev/null | grep -v '^\s*$' | grep -v '^Default' \
    | grep -v '^Include' | while read -r line; do
      log "  $line"
    done
fi

# sudoers.d drop-ins
if [[ -d /etc/sudoers.d ]]; then
  for f in /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    log "  [sudoers.d] $f"
    grep -v '^\s*#' "$f" | grep -v '^\s*$' | while read -r line; do
      log "    $line"
    done
  done
fi

# Members of 'sudo' or 'wheel' group
for grp in sudo wheel; do
  members="$(getent group "$grp" 2>/dev/null | cut -d: -f4)"
  if [[ -n "$members" ]]; then
    log "  Group '$grp' members: $members"
  fi
done
log ""

# ── Section 3: Last login times (all users) ───────────────────────────────────
log "  [3] Recent login activity (last 10)"
log "  $(printf -- '-%.0s' {1..58})"
last -n 10 2>/dev/null | head -10 | while read -r line; do
  log "  $line"
done
log ""

# ── Section 4: Currently logged-in users ──────────────────────────────────────
log "  [4] Currently logged-in users"
log "  $(printf -- '-%.0s' {1..58})"
who 2>/dev/null | while read -r line; do
  log "  $line"
done
log ""

# ── Section 5: Summary & alert ────────────────────────────────────────────────
log "$DIVIDER"
if [[ "$ALERT_COUNT" -gt 0 ]]; then
  log "  [!] ALERT: $ALERT_COUNT unexpected user(s) found with login shells."
  log "  Review the entries marked UNEXPECTED above."

  if [[ -n "$ALERT_EMAIL" ]] && command -v mail &>/dev/null; then
    log "  Sending alert email to: $ALERT_EMAIL"
    echo "Linux audit found $ALERT_COUNT unexpected user(s). See attached report." \
      | mail -s "[SECURITY] Linux User Audit Alert" "$ALERT_EMAIL"
  fi

  log "$DIVIDER"
  exit 1
else
  log "  [OK] All users with login shells are on the whitelist."
  log "$DIVIDER"
  exit 0
fi
