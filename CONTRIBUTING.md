# Contributing to sigil

## Workflow

- Work happens on feature branches: `feat/<layer>`, `fix/<short>`, or `chore/<short>`.
- Push the branch and open a PR against `main`.
- PR description links the issue with a `Refs #N` or `Closes #N` trailer.
- CI must pass before merge. The required check is `Test (Node 22)`.
- Squash-merge only (linear history on `main`).
- Delete the branch after merge.

Direct pushes to `main` are blocked by branch protection. Repo admins can bypass in an emergency, but should still prefer the PR path.

## Local development

```sh
npm install   # respects .npmrc (ignore-scripts=true)
npm test      # tsc + node --test 'dist/test/**/*.test.js'
```

Tests must pass locally before pushing.

## Commit messages

- Subject line under 70 characters, imperative mood ("Add X", not "Added X").
- Body explains the **why**. The diff already shows the **what**.
- No `Co-Authored-By` trailers.
- Reference issues with `Refs #N` (partial work) or `Closes #N` (completes the issue).

## Security

Never commit:
- `.env`, `.env.*`
- `*.pem`, `*.key`, `*.keystore`
- Anything inside `~/.sigil/` or a project-local `.sigil/`

The repo `.gitignore` covers these patterns. Double-check `git status` before committing.

For security issues in sigil itself, open a private GitHub Security Advisory rather than a public issue.

## Releasing (maintainer only)

`sigild` publishes to npm via OIDC trusted-publisher auth — there is no long-lived `NPM_TOKEN`. The release workflow at [`.github/workflows/release.yml`](./.github/workflows/release.yml) is the only thing allowed to publish; it triggers on tags matching `v*`.

To cut a new release:

1. Land a PR that bumps `package.json` `version` and `server.json` `version` + the inner `packages[0].version` (both must match). Get it into `main`.
2. Pull `main` locally so your working tree matches the merged commit.
3. Tag and push:
   ```sh
   git tag v0.0.4 && git push --tags
   ```
4. The workflow runs: installs, tests, verifies the tag matches `package.json`, then `npm publish --access public --provenance`. If anything fails, no publish happens.
5. Optionally: also publish to the MCP registry. `mcp-publisher login github` (if your local token expired) then `mcp-publisher publish`. There's no automated path for the MCP registry yet.

One-time setup on `npmjs.com` (already done — listed here for documentation):

- Package settings → Trusted publishers → Add → GitHub Actions
- Organization or user: `cdrn`
- Repository: `sigil`
- Workflow filename: `release.yml`
- Environment name: `release`

If that config is ever lost or rotated, every step above will fail with an OIDC auth error until it's recreated. No fallback token by design.
