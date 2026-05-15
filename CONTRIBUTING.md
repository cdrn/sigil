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
