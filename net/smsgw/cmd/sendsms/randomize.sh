#!/bin/sh
set -e
set -u

g_csv="${1:-}"

fn_help() {
   echo "USAGE"
   echo "   # sort -R ./list.csv > ./list.csv.bak"
   echo "   ./randomize.sh ./list.csv"
}

fn_tip() {
   echo "IMPORTANT"
   echo "    Now go move the header back to the first row"
}

main() {
   if test -z "${g_csv}" || ! test -s "${g_csv}"; then
      >&2 fn_help
      return 1
   fi

   if test -s "${g_csv}.randomized"; then
      {
         echo "${g_csv}.randomized already exists"
         fn_tip
      } >&2
      return 1
   fi

   sort -R "${g_csv}" > "${g_csv}.randomized"
   {
      echo "wrote ${g_csv}.randomized"
      fn_tip
   } >&2
}

main
