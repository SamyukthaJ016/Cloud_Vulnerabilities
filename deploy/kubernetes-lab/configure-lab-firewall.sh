#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
: "${CLOUDGUARD_SOURCE_IP:?Set the CloudGuard worker public IPv4 address}"
: "${ADMIN_SOURCE_IP:?Set the administrator public IPv4 address}"

ufw default deny incoming
ufw default allow outgoing
ufw allow from "${ADMIN_SOURCE_IP}" to any port 22 proto tcp comment 'CloudGuard lab administrator'
if [[ -n "${SECOND_ADMIN_SOURCE_IP:-}" ]]; then
  ufw allow from "${SECOND_ADMIN_SOURCE_IP}" to any port 22 proto tcp comment 'CloudGuard lab administrator'
fi
ufw allow from "${CLOUDGUARD_SOURCE_IP}" to any port 6443 proto tcp comment 'CloudGuard scanner API'
ufw allow in on cni0 from 10.42.0.0/16 comment 'K3s pods'
ufw allow in on flannel.1 from 10.42.0.0/16 comment 'K3s overlay'
ufw route allow in on cni0 out on cni0
ufw route allow in on cni0 out on eth0
ufw --force enable

# Drop public service traffic before Kubernetes can DNAT NodePorts past UFW.
iptables -t raw -C PREROUTING -i eth0 -p tcp -m multiport --dports 80,443,30000:32767 -j DROP 2>/dev/null || \
  iptables -t raw -I PREROUTING 1 -i eth0 -p tcp -m multiport --dports 80,443,30000:32767 -j DROP
iptables -t raw -C PREROUTING -i eth0 -p udp -m multiport --dports 8472,30000:32767 -j DROP 2>/dev/null || \
  iptables -t raw -I PREROUTING 1 -i eth0 -p udp -m multiport --dports 8472,30000:32767 -j DROP
ip6tables -t raw -C PREROUTING -i eth0 -p tcp -m multiport --dports 80,443,30000:32767 -j DROP 2>/dev/null || \
  ip6tables -t raw -I PREROUTING 1 -i eth0 -p tcp -m multiport --dports 80,443,30000:32767 -j DROP
ip6tables -t raw -C PREROUTING -i eth0 -p udp -m multiport --dports 8472,30000:32767 -j DROP 2>/dev/null || \
  ip6tables -t raw -I PREROUTING 1 -i eth0 -p udp -m multiport --dports 8472,30000:32767 -j DROP

ufw status verbose
