#!/bin/sh

# 2020-02-20 02:20:22
g_ts=$(date '+%F %T')
. ./.env

curl --fail-with-body -X POST "${SMSGW_BASEURL}/messages" \
   --user "${SMSGW_USERNAME}:${SMSGW_PASSWORD}" \
   -H 'Content-Type: application/json' \
   --data-binary '
      {
         "textMessage":{
            "text": "Test message. It'\''s '"${g_ts}"'"
         },
         "phoneNumbers": ["'"${SMSGW_TEST_NUMBER}"'"],
         "priority":65
      }
   '
