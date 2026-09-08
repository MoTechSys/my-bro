# CI workflow — pending activation

`validate.yml` runs `scripts/validate/validate_all.sh` on every push/PR.
The AI agent's GitHub token has no `workflows` permission, so it cannot create files under `.github/workflows/`.

**To enable (a team member with repo write access):**
```bash
git mv .github/workflows-pending/validate.yml .github/workflows/validate.yml
git commit -m "ci: enable validate workflow" && git push
```
