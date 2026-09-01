#!/usr/bin/env bash

set -Eeuo pipefail

KCADM=/opt/keycloak/bin/kcadm.sh
KCADM_CONFIG=/tmp/kcadm.config
KEYCLOAK_URL=${KEYCLOAK_URL:-http://keycloak:8080/auth}
KEYCLOAK_REALM=${KEYCLOAK_REALM:-gigachad-grc}
PROFILE_FILE=${PROFILE_FILE:-/opt/keycloak/config/user-profile.json}

authenticated=false
for _attempt in {1..30}; do
  if "$KCADM" config credentials \
    --server "$KEYCLOAK_URL" \
    --realm master \
    --user "$KEYCLOAK_ADMIN" \
    --password "$KEYCLOAK_ADMIN_PASSWORD" \
    --config "$KCADM_CONFIG" >/dev/null 2>&1; then
    authenticated=true
    break
  fi
  sleep 2
done

if [ "$authenticated" != true ]; then
  echo "Unable to authenticate to Keycloak administration" >&2
  exit 1
fi

"$KCADM" update users/profile \
  -r "$KEYCLOAK_REALM" \
  -f "$PROFILE_FILE" \
  --config "$KCADM_CONFIG" >/dev/null

rm -f "$KCADM_CONFIG"
echo "Keycloak user profile configured"
