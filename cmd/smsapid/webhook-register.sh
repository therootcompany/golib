#!/bin/sh
set -e
set -u

. ./.env

# https://docs.sms-gate.app/features/webhooks/

cmd_curl="curl --fail-with-body -sS"
g_events="sms:sent sms:delivered sms:failed sms:received mms:received sms:data-received system:ping"

fn_delete_all() { (
    b_json="$(
        $cmd_curl "${SMSGW_BASEURL}/webhooks" \
            -u "${SMSGW_USER}:${SMSGW_PASSWORD}"
    )"
    echo "${b_json}" | jq

    echo "${b_json}" | jq -r '.[] | "\(.id) \(.event) \(.url)"' | while read -r b_id b_event b_url; do
        echo >&2 "Deleting webhook ${b_id} ${b_url} ${b_event}"
        $cmd_curl -X DELETE "${SMSGW_BASEURL}/webhooks/${b_id}" \
            -u "${SMSGW_USER}:${SMSGW_PASSWORD}"
    done
); }

fn_subscribe_all() { (
    for b_event in $g_events; do
        echo >&2 "Subscribing to ${b_event}"
        $cmd_curl "${SMSGW_BASEURL}/webhooks" \
            -u "${SMSGW_USER}:${SMSGW_PASSWORD}" \
            -H 'Content-Type: application/json' \
            -d '{
                   "url": "https://smsgateway.lab1.therootcompany.com/api/log",
                   "event": "'"${b_event}"'"
                }' | jq
        printf '\n'
        sleep 0.1
    done
); }

printf '\nPurging all existing webooks\n'
fn_delete_all

printf '\nExisting webhooks\n'
$cmd_curl "${SMSGW_BASEURL}/webhooks" \
    -u "${SMSGW_USER}:${SMSGW_PASSWORD}" | jq

printf '\nSubscribe to all webooks\n'
fn_subscribe_all

printf 'Current webooks\n'
$cmd_curl "${SMSGW_BASEURL}/webhooks" \
    -u "${SMSGW_USER}:${SMSGW_PASSWORD}" | jq

printf 'OK\n'
