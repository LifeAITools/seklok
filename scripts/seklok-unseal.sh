#!/usr/bin/env bash
# seklok-unseal — bulk-unseal projects after a server restart, without storing
# master keys on the server's filesystem.
#
# Usage:
#   seklok-unseal --keyfile <path>             # use a JSON keyfile (mode 0600)
#   seklok-unseal --1password "Seklok Vault"   # fetch keys from 1Password CLI
#   seklok-unseal --pass seklok/               # fetch keys from `pass`
#   seklok-unseal --interactive                # prompt per project
#
# Auth: requires admin Basic Auth credentials in env (SEKLOK_ADMIN_USER,
# SEKLOK_ADMIN_PASS) or a session cookie file (SEKLOK_SESSION_COOKIE).
#
# Why this script and not auto-unseal? Because storing master keys on the host
# undermines the seal-by-default model. With this script you keep the keys in
# your password manager and run it *manually* after each restart. The keys
# never persist on the seklok server — only in the operator's memory + their
# password vault.

set -euo pipefail

usage() {
  cat <<EOF
Usage:
  $0 --url <seklok-url> --keyfile <path>
  $0 --url <seklok-url> --1password <vault-name>
  $0 --url <seklok-url> --pass <pass-prefix>
  $0 --url <seklok-url> --interactive

Required env:
  SEKLOK_ADMIN_USER       Basic Auth username for /admin/* endpoints
  SEKLOK_ADMIN_PASS       Basic Auth password

Or:
  SEKLOK_SESSION_COOKIE   Path to a file containing a 'seklok_session=<token>' cookie

Examples:
  SEKLOK_ADMIN_USER=admin SEKLOK_ADMIN_PASS=*** \\
    $0 --url https://secrets.muid.io --keyfile ~/seklok-keys.json

  SEKLOK_ADMIN_USER=admin SEKLOK_ADMIN_PASS=*** \\
    $0 --url https://secrets.muid.io --1password "Personal"

  SEKLOK_ADMIN_USER=admin SEKLOK_ADMIN_PASS=*** \\
    $0 --url https://secrets.muid.io --pass seklok/
EOF
  exit 1
}

URL=""
MODE=""
ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --keyfile) MODE="keyfile"; ARG="$2"; shift 2 ;;
    --1password) MODE="1password"; ARG="$2"; shift 2 ;;
    --pass) MODE="pass"; ARG="$2"; shift 2 ;;
    --interactive) MODE="interactive"; shift ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1"; usage ;;
  esac
done

[[ -z "$URL" ]] && { echo "error: --url is required" >&2; usage; }
[[ -z "$MODE" ]] && { echo "error: one of --keyfile / --1password / --pass / --interactive is required" >&2; usage; }

# Auth setup
AUTH_ARGS=()
if [[ -n "${SEKLOK_ADMIN_USER:-}" && -n "${SEKLOK_ADMIN_PASS:-}" ]]; then
  AUTH_ARGS=(-u "${SEKLOK_ADMIN_USER}:${SEKLOK_ADMIN_PASS}")
elif [[ -n "${SEKLOK_SESSION_COOKIE:-}" && -f "$SEKLOK_SESSION_COOKIE" ]]; then
  AUTH_ARGS=(-b "$SEKLOK_SESSION_COOKIE")
else
  echo "error: set SEKLOK_ADMIN_USER+SEKLOK_ADMIN_PASS or SEKLOK_SESSION_COOKIE" >&2
  exit 2
fi

# Discover projects
echo "→ discovering projects on ${URL}..."
PROJECTS_HTML=$(curl -fsS "${AUTH_ARGS[@]}" "${URL}/admin/projects")
# Extract id, name, sealed/unsealed status from table rows
PROJECTS=$(echo "$PROJECTS_HTML" | python3 -c '
import sys, re
html = sys.stdin.read()
rows = re.findall(r"<tr>(.*?)</tr>", html, re.S)
for r in rows:
    cells = re.findall(r"<td>(.*?)</td>", r, re.S)
    if len(cells) >= 3:
        pid = re.sub(r"\s+", "", cells[0])
        name = re.sub(r"<[^>]+>", "", cells[1]).strip()
        status = re.sub(r"<[^>]+>", "", cells[2]).strip()
        if pid.isdigit():
            print(f"{pid}\t{name}\t{status}")
' 2>/dev/null || true)

if [[ -z "$PROJECTS" ]]; then
  echo "error: could not parse project list. Is admin auth correct?" >&2
  exit 3
fi

echo ""
echo "Projects found:"
echo "$PROJECTS" | awk -F$'\t' '{printf "  [%s] %-30s %s\n", $1, $2, $3}'
echo ""

# Iterate sealed ones
SEALED=$(echo "$PROJECTS" | awk -F$'\t' '$3 == "sealed" {print $1 "\t" $2}')

if [[ -z "$SEALED" ]]; then
  echo "✓ no sealed projects — nothing to do."
  exit 0
fi

unseal_one() {
  local pid="$1" name="$2" key="$3"
  local resp http_code
  resp=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "${AUTH_ARGS[@]}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "master_key=${key}" \
    "${URL}/admin/projects/${pid}/unseal")
  http_code="$resp"
  if [[ "$http_code" =~ ^3[0-9][0-9]$ ]]; then
    echo "  ✓ unsealed [${pid}] ${name}"
    return 0
  else
    echo "  ✗ FAILED [${pid}] ${name} (HTTP ${http_code}) — wrong key?"
    return 1
  fi
}

fetch_key_keyfile() {
  local pid="$1"
  python3 -c "
import json, sys
try:
    d = json.load(open('${ARG}'))
    print(d.get('${pid}', ''), end='')
except Exception as e:
    print('', end='')
"
}

fetch_key_1password() {
  local pid="$1" name="$2"
  # Conventionally store as: vault item titled 'Seklok-<name>' with field 'master_key'
  op item get "Seklok-${name}" --vault "${ARG}" --fields label=master_key 2>/dev/null || true
}

fetch_key_pass() {
  local pid="$1" name="$2"
  pass show "${ARG}${name}" 2>/dev/null | head -1 || true
}

fetch_key_interactive() {
  local pid="$1" name="$2"
  read -rsp "  master key for [${pid}] ${name}: " k
  echo ""
  echo "$k"
}

OK=0
FAIL=0
while IFS=$'\t' read -r pid name; do
  echo "→ [${pid}] ${name}"
  case "$MODE" in
    keyfile)     KEY=$(fetch_key_keyfile "$pid") ;;
    1password)   KEY=$(fetch_key_1password "$pid" "$name") ;;
    pass)        KEY=$(fetch_key_pass "$pid" "$name") ;;
    interactive) KEY=$(fetch_key_interactive "$pid" "$name") ;;
  esac

  if [[ -z "$KEY" ]]; then
    echo "  ⚠ no key found for [${pid}] ${name}, skipping"
    FAIL=$((FAIL + 1))
    continue
  fi

  if unseal_one "$pid" "$name" "$KEY"; then
    OK=$((OK + 1))
  else
    FAIL=$((FAIL + 1))
  fi
done <<< "$SEALED"

echo ""
echo "summary: ${OK} unsealed, ${FAIL} failed/skipped"
[[ $FAIL -gt 0 ]] && exit 1 || exit 0
