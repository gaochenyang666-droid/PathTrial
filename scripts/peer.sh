#!/bin/sh
# Start a temporary PathTrial peer on a machine you control.
# This script does not change firewall rules, DNS, routes, or system proxy
# settings. If a firewall drops the ports, open them yourself.

set -eu

binary=${PATHTRIAL_BIN:-pathtrial}
task=${1:?usage: scripts/peer.sh TASK_ID LISTEN_IP:PORT UDP_IP:PORT [SECONDS]}
listen=${2:?usage: scripts/peer.sh TASK_ID LISTEN_IP:PORT UDP_IP:PORT [SECONDS]}
udp=${3:?usage: scripts/peer.sh TASK_ID LISTEN_IP:PORT UDP_IP:PORT [SECONDS]}
seconds=${4:-120}
output=${PATHTRIAL_PEER_OUTPUT:-pathtrial-peer-collect.json}

case "$task$listen$udp" in
    *";"*) printf 'error: task, listen, and udp values must not contain ;\n' >&2; exit 1 ;;
esac

printf '%s\n' "PathTrial will not change firewall, DNS, or routes."
printf '%s\n' "If those ports are filtered, that is outside this script."
printf '%s\n' "UDP echo payloads are not stored. Collect JSON: $output"
exec "$binary" endpoint --peer \
    --task-id "$task" \
    --listen "$listen" \
    --bind "$udp" \
    --allow-public-bind \
    --max-seconds "$seconds" \
    --output "$output"
