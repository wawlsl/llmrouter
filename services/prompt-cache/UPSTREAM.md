# PromptCache Vendor Notes

This directory vendors PromptCache source code into this monorepo.

- Upstream project: https://github.com/messkan/prompt-cache
- Local path: `services/prompt-cache`
- Runtime data path (default in this repo): `data/promptcache`

When updating PromptCache from upstream, replace this directory and keep repo-level scripts/docs in sync:

- `scripts/cache-server.sh`
- `package.json` scripts (`cache:*`)
- `README.md` integration sections
