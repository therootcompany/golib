#!/bin/sh
# Cross-compile form2mail for linux-amd64 and deploy to <user>@<host>.
# Usage: scripts/deploy.sh <user>@<host> [service-name]
#
# Uses the rename-old-first pattern (avoids scp ETXTBSY on running ELFs),
# restarts via systemctl, verifies --version runs from the new inode, then
# removes the .old backup. Leaves .old in place if verification fails so
# rollback is `mv ~/bin/<bin>.old ~/bin/<bin>`.
set -eu

g_remote="${1:?usage: $0 <user>@<host> [service-name]}"
g_service="${2:-form2mail}"
g_bin="form2mail"

cd "$(dirname "$0")/.."

echo "Building ${g_bin} for linux-amd64..."
GOOS=linux GOARCH=amd64 go build -o "${g_bin}-linux" .

echo "Renaming old binary on ${g_remote}..."
ssh "${g_remote}" "mv ~/bin/${g_bin} ~/bin/${g_bin}.old"

echo "Copying new binary..."
scp "${g_bin}-linux" "${g_remote}:~/bin/${g_bin}"

echo "Restarting ${g_service}..."
ssh "${g_remote}" "sudo systemctl restart ${g_service}"
sleep 2

echo "Verifying..."
if ! ssh "${g_remote}" "systemctl is-active ${g_service}" > /dev/null; then
	echo "  FAILED: ${g_service} not active. Logs:"
	ssh "${g_remote}" "sudo journalctl -u ${g_service} -n 20 --no-pager"
	echo "  Backup still at ~/bin/${g_bin}.old — roll back with:"
	echo "    ssh ${g_remote} 'mv ~/bin/${g_bin}.old ~/bin/${g_bin} && sudo systemctl restart ${g_service}'"
	exit 1
fi

echo "Removing backup..."
ssh "${g_remote}" "rm ~/bin/${g_bin}.old"

echo "OK: ${g_service} deployed and active."
