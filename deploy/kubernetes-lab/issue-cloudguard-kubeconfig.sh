#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi

: "${K3S_API_HOST:?Set K3S_API_HOST to the private IP or DNS name reachable from the CloudGuard worker}"

OUTPUT_PATH="${OUTPUT_PATH:-/root/cloudguard-kubeconfig.yaml}"
TOKEN_DURATION="${TOKEN_DURATION:-720h}"
SERVER_URL="https://${K3S_API_HOST}:6443"

token="$(k3s kubectl create token cloudguard-lab-worker \
  --namespace cloudguard-system \
  --duration "${TOKEN_DURATION}")"
ca_data="$(base64 -w 0 /var/lib/rancher/k3s/server/tls/server-ca.crt)"

umask 077
cat > "${OUTPUT_PATH}" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: cloudguard-lab
    cluster:
      server: ${SERVER_URL}
      certificate-authority-data: ${ca_data}
contexts:
  - name: cloudguard-lab
    context:
      cluster: cloudguard-lab
      user: cloudguard-lab-worker
current-context: cloudguard-lab
users:
  - name: cloudguard-lab-worker
    user:
      token: ${token}
EOF

chmod 600 "${OUTPUT_PATH}"

KUBECONFIG="${OUTPUT_PATH}" kubectl get namespaces >/dev/null
KUBECONFIG="${OUTPUT_PATH}" kubectl auth can-i create namespaces | grep -qx yes
KUBECONFIG="${OUTPUT_PATH}" kubectl auth can-i create rolebindings --all-namespaces | grep -qx yes

echo "Kubeconfig written to ${OUTPUT_PATH}."
echo "Store it in CloudGuard Manage Credentials; do not email or commit it."
echo "Token duration requested: ${TOKEN_DURATION}. Rotate it before expiry."
