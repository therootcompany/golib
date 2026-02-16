#!/bin/sh

set -e

rm -f all.*

find . -type f \( -name '*.go' -o -name '*.sql' \) -print | sort | while IFS= read -r file; do
   # Skip files named all.* (case sensitive)
   case "$(basename "$file")" in
      all.*) continue ;;
   esac

   # Choose comment style based on file extension
   case "$file" in
      *.go)
         {
            printf '\n// %s\n\n' "$file"
            cat "$file"
            printf '\n'
         } >> all.go
         ;;
      *.sql)
         {
            printf '\n-- %s\n\n' "$file"
            cat "$file"
            printf '\n'
         } >> all.sql
         ;;
      *)
         {
            printf '\n# %s\n\n' "$file"
            cat "$file"
            printf '\n'
         } >> all.md
         ;;
   esac
done
