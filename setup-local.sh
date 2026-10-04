#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
if [ ! -f .env ]; then
  node --input-type=module -e 'import { randomBytes } from "node:crypto"; import { writeFileSync } from "node:fs"; writeFileSync(".env", "ACCESS_TOKEN=" + randomBytes(32).toString("hex") + "\nSOURCE_AUTHORIZATION=\nSYNC_INTERVAL_SECONDS=300\n", {flag:"wx",mode:0o600});'
fi
if [ ! -f sources.json ]; then
  printf '%s\n' '{"sources":[]}' > sources.json
fi
chmod 600 .env sources.json
printf '%s\n' 'Configuration ready. Add sources to sources.json when ready.'
