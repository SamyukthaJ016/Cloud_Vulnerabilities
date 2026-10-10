#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

: "${K3S_API_HOST:?Set K3S_API_HOST to the private IP or DNS name reachable from the CloudGuard worker}"

K3S_CHANNEL="${K3S_CHANNEL:-stable}"

echo "Installing a single-node CloudGuard lab cluster for ${K3S_API_HOST}..."
curl -sfL https://get.k3s.io | \
  INSTALL_K3S_CHANNEL="${K3S_CHANNEL}" \
  sh -s - server \
    --disable traefik \
    --disable servicelb \
    --tls-san "${K3S_API_HOST}" \
    --write-kubeconfig-mode 600

echo "Waiting for the Kubernetes API..."
for _ in $(seq 1 60); do
  if k3s kubectl get --raw=/readyz >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

k3s kubectl get --raw=/readyz >/dev/null
for _ in $(seq 1 60); do
  if [[ -n "$(k3s kubectl get nodes -o name)" ]]; then
    break
  fi
  sleep 2
done
k3s kubectl wait --for=condition=Ready node --all --timeout=180s

k3s kubectl create namespace cloudguard-system \
  --dry-run=client -o yaml | k3s kubectl apply -f -
k3s kubectl create serviceaccount cloudguard-lab-worker \
  --namespace cloudguard-system \
  --dry-run=client -o yaml | k3s kubectl apply -f -
k3s kubectl create clusterrolebinding cloudguard-lab-worker-admin \
  --clusterrole cluster-admin \
  --serviceaccount cloudguard-system:cloudguard-lab-worker \
  --dry-run=client -o yaml | k3s kubectl apply -f -

echo
echo "CloudGuard lab cluster is ready."
echo "Next: run issue-cloudguard-kubeconfig.sh on this VM."
