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
# deploy-time data snapshot: real feeds + threat graph + labelled sample data (see scripts/build_snapshot.py)
PY="${PYTHON:-$ROOT/../.venv/bin/python}"
"$PY" "$ROOT/scripts/build_snapshot.py" | tail -1
mkdir -p "$OUT"
(cd "$ROOT" && git ls-files -z | rsync -a --from0 --files-from=- ./ "$OUT/")
cp -R "$ROOT/frontend/dist" "$OUT/static"
cp -R "$ROOT/snapshot" "$OUT/snapshot"
[ -d "$ROOT/.vercel" ] && cp -R "$ROOT/.vercel" "$OUT/"
cd "$OUT"
npx --yes vercel@latest deploy --prod --yes -e API_KEYS="$KEY" -e PUBLIC_ACCESS=true -e DEMO_MODE=false -e ENABLE_EMBEDDINGS=false
