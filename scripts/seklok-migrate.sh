#!/bin/bash
# seklok-migrate <project-name> <env-file>
#
# Migrate a service's secrets into the seklok vault (secrets.muid.io, production
# env) and issue a runtime read-token. Codified from the km-ts pilot — see
# seklok/PRPs/secrets-migration/01-idea.md. IDEMPOTENT: re-running upserts secrets
# and reuses the project.
#
# 🔴 RUN ON muid.io AS root (needs docker access to read the seklok admin creds
#    from the seklok-ts container env, sqlite access to the vault DB, and write
#    access to unseal.json). Example:  ssh root@muid.io 'bash -s' < seklok-migrate.sh km-ts /opt/km-ts/.env
#
# What it does NOT do (service-specific, do by hand after):
#   - wire the service to fetch from seklok (add src/seklok.ts + src/bootstrap.ts,
#     import bootstrap first; pattern in km-ts) and set SEKLOK_TOKEN in its deploy env;
#   - remove the plaintext secrets from the service compose/.env + redeploy + verify.
set -uo pipefail

PROJECT="${1:-}"; ENVFILE="${2:-}"
[ -n "$PROJECT" ] && [ -n "$ENVFILE" ] || { echo "usage: seklok-migrate <project-name> <env-file>" >&2; exit 2; }
[ -f "$ENVFILE" ] || { echo "env-file not found: $ENVFILE" >&2; exit 1; }

BASE="https://secrets.muid.io"
DB=/opt/seklok/data/seklok.db
UNSEAL=/opt/seklok/secrets/unseal.json
PROD_ENV_ID=3   # 1=development 2=staging 3=production (environments table is GLOBAL)

# Admin creds — read from the running container; NEVER printed.
AU=$(docker inspect seklok-ts --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^ADMIN_BASIC_AUTH_USERNAME=' | cut -d= -f2-)
AP=$(docker inspect seklok-ts --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^ADMIN_BASIC_AUTH_PASSWORD=' | cut -d= -f2-)
[ -n "$AU" ] && [ -n "$AP" ] || { echo "could not read seklok admin creds from seklok-ts container" >&2; exit 1; }

# mktok <pid> <friendly_name> <right...> -> echoes the public token (scraped from the once-shown reveal)
mktok() {
  local pid="$1" fn="$2"; shift 2
  local a=(--data-urlencode "friendly_name=$fn" --data-urlencode "environment_id=$PROD_ENV_ID") r
  for r in "$@"; do a+=(--data-urlencode "rights=$r"); done
  curl -s -u "$AU:$AP" -X POST "$BASE/admin/projects/$pid/service-tokens" "${a[@]}" \
    | grep -oE '[A-Za-z0-9_.+/=-]{40,}' | sort -u | awk '{print length,$0}' | sort -rn | head -1 | cut -d' ' -f2-
}

# 1) Project — reuse if it exists, else create + persist master key to unseal.json + unseal.
PID=$(sqlite3 "$DB" "SELECT id FROM projects WHERE name='$PROJECT' ORDER BY id DESC LIMIT 1;")
if [ -n "$PID" ]; then
  echo "project '$PROJECT' exists (#$PID) — reusing"
  MK=$(python3 -c "import json,sys;print(json.load(open('$UNSEAL')).get('$PID',''))" 2>/dev/null)
  if [ -n "$MK" ]; then curl -s -o /dev/null -u "$AU:$AP" -X POST "$BASE/admin/projects/$PID/unseal" --data-urlencode "master_key=$MK"; fi
else
  RESP=$(curl -s -u "$AU:$AP" -X POST "$BASE/admin/projects" --data-urlencode "name=$PROJECT" --data-urlencode "description=migrated by seklok-migrate")
  MK=$(printf '%s' "$RESP" | grep -oE '[A-Za-z0-9+/]{40,}={0,2}' | head -1)
  PID=$(sqlite3 "$DB" "SELECT id FROM projects WHERE name='$PROJECT' ORDER BY id DESC LIMIT 1;")
  [ -n "$MK" ] && [ -n "$PID" ] || { echo "project creation/extraction failed (MK len=${#MK}, PID=$PID)" >&2; exit 1; }
  python3 -c "import json,sys;f='$UNSEAL';d=json.load(open(f));d['$PID']=sys.argv[1];json.dump(d,open(f,'w'))" "$MK"
  curl -s -o /dev/null -u "$AU:$AP" -X POST "$BASE/admin/projects/$PID/unseal" --data-urlencode "master_key=$MK"
  echo "project '$PROJECT' created (#$PID) — master key persisted to unseal.json (auto-unseal) + unsealed"
fi

# 2) Loader token (read+write+admin) to upsert secrets.
ATOK=$(mktok "$PID" "seklok-migrate-loader" read write admin)
[ -n "$ATOK" ] || { echo "loader token creation failed" >&2; exit 1; }
EXISTING=$(curl -s -H "Authorization: Bearer $ATOK" "$BASE/api/v1/secrets")

# 3) Upsert each KEY=VALUE from the env-file (skip comments + empty values).
created=0; updated=0; skipped=0
while IFS='=' read -r k v; do
  [ -z "$k" ] && continue; case "$k" in \#*) continue;; esac
  v="${v%\"}"; v="${v#\"}"; [ -z "$v" ] && { skipped=$((skipped+1)); continue; }
  sid=$(printf '%s' "$EXISTING" | python3 -c "import sys,json;d=json.load(sys.stdin);print(next((s['id'] for s in d.get('secrets',[]) if s['name']==sys.argv[1]),''))" "$k" 2>/dev/null)
  if [ -n "$sid" ]; then
    curl -s -o /dev/null -X PUT "$BASE/api/v1/secrets/$sid" -H "Authorization: Bearer $ATOK" -H "Content-Type: application/json" \
      --data "$(python3 -c 'import json,sys;print(json.dumps({"value":sys.argv[1]}))' "$v")" && updated=$((updated+1))
  else
    curl -s -o /dev/null -X POST "$BASE/api/v1/secrets" -H "Authorization: Bearer $ATOK" -H "Content-Type: application/json" \
      --data "$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1],"value":sys.argv[2]}))' "$k" "$v")" && created=$((created+1))
  fi
done < "$ENVFILE"
echo "secrets: $created created, $updated updated, $skipped skipped(empty)"

# 4) Runtime read-only token → written to a 600 stash next to the env-file (NOT printed to stdout/logs).
RTOK=$(mktok "$PID" "$PROJECT-runtime" read)
[ -n "$RTOK" ] || { echo "runtime token creation failed" >&2; exit 1; }
STASH="$(dirname "$ENVFILE")/.seklok-runtime-token"
umask 077; printf '%s' "$RTOK" > "$STASH"
echo
echo "=== DONE: '$PROJECT' migrated (seklok project #$PID) ==="
echo "Runtime token written to: $STASH (chmod 600 — never commit it)"
echo "Next (service-specific): set SEKLOK_TOKEN=\$(cat $STASH) in the deploy env, add"
echo "src/seklok.ts + src/bootstrap.ts (bootstrap imported first), remove the plaintext"
echo "secrets from the service compose/.env, redeploy, and verify the '[seklok] hydrated' log."
