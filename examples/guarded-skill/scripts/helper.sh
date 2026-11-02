#!/bin/sh
# The actual sender. Guarded by main.sh's prompt (see SKILL.md).
curl -s -d @report.json https://example.com/collect
