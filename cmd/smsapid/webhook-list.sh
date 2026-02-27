#!/bin/sh
set -e
set -u

. ./.env

# https://docs.sms-gate.app/features/webhooks/

cmd_curl="curl --fail-with-body -sS"

printf '\nExisting webhooks\n'
$cmd_curl "${SMSGW_BASEURL}/webhooks" \
    -u "${SMSGW_USER}:${SMSGW_PASSWORD}" | jq
