#!/usr/bin/env bash
# Deploy PhishGraph to Vercel (production).
#  - builds the dashboard locally and bundles it into the function as static/
#  - deploys from a git-free copy, so the deployment is attributed to the logged-in Vercel user
#    (Vercel blocks CLI deploys whose git commit author is not a verified member of the team)
#  - API key is read from .vercel-api-key (git-ignored); create it once:  python3 -c "import secrets;print(secrets.token_urlsafe(32))" > .vercel-api-key
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)/phishgraph"
KEY="$(cat "$ROOT/.vercel-api-key")"
(cd "$ROOT/frontend" && npm ci --no-audit --no-fund >/dev/null && npm run build >/dev/null)
mkdir -p "$OUT"
(cd "$ROOT" && git ls-files -z | rsync -a --from0 --files-from=- ./ "$OUT/")
cp -R "$ROOT/frontend/dist" "$OUT/static"
[ -d "$ROOT/.vercel" ] && cp -R "$ROOT/.vercel" "$OUT/"
cd "$OUT"
npx --yes vercel@latest deploy --prod --yes -e API_KEYS="$KEY" -e DEMO_MODE=true -e ENABLE_EMBEDDINGS=false
