#!/bin/sh
# Thin entry script: ask first, then hand off to the helper that
# actually does the sending. v0.1 flagged the helper as a
# contradiction because the prompt was not in its file; v0.2 follows
# the call and honours the guard.
read -p 'Send the report? (y/n) ' ans
[ "$ans" = "y" ] || exit 0
./helper.sh
