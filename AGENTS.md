# Git and Change Budget Contract

These rules apply to every task that modifies repository files. They authorize safe local Git management only. Follow `CONTRIBUTING.md` for repository-specific validation.

## Branch Model

- `origin/main` is the authoritative GitHub base; local `main` mirrors it and receives no task commits.
- `lijunjie` is the persistent local development branch based on `main`.
- Create or reuse `agent/<task-slug>` from the current `lijunjie` commit for every modifying task.

## Start Gate

Before editing, run:

```sh
git status --short --branch
git rev-parse HEAD
git diff --stat
```

Record the starting branch and base SHA. Treat all existing modified or untracked files as user-owned: never stage, stash, overwrite, discard, or commit them. If a target file is already modified, stop and ask the user.

Create the task branch, then tag its base:

```sh
git tag ai-checkpoint/<UTC-timestamp>-<task-slug> <base-sha>
```

Local task branches, checkpoint tags, and ordinary local commits are authorized.

## Change Budget

Before editing, state the exact goal, acceptance criteria, expected files, targeted tests, and estimated changed lines.

- Per commit: at most 4 hand-edited files and 200 changed lines.
- Per task: at most 8 hand-edited files and 400 changed lines.
- Split larger work into independently testable units; exceeding the task limit requires explicit approval.
- Report generated files and lockfiles separately. Ask before adding binaries or more than 500 generated lines.

## Minimal Implementation

Implement only the requested behavior and necessary tests. Reuse existing code and conventions. Avoid unrelated cleanup, formatting, speculative abstractions, compatibility layers, retries, fallbacks, or defensive checks unless required by acceptance criteria, an existing test, or a demonstrated failure. Do not add dependencies without explicit approval or create parallel implementations when an existing module can be changed directly.

## Atomic Commit Loop

For each independent change:

1. Make one small, coherent modification.
2. Run the narrowest relevant tests.
3. Run `git diff --check`.
4. Review the complete diff and verify the budget.
5. Stage only task files with `git add -- <explicit-paths>`; never use `git add .` or `git add -A`.
6. Inspect `git diff --cached`.
7. Commit only coherent, required, verified work with a specific message.

Never commit broken, partial, or unverified work.

## Recovery and Remote Boundary

After every commit, record its SHA and report:

```sh
git revert <commit-sha>
```

List multiple revert commands newest first. Also report, but do not execute:

```sh
git switch -c recovery/<task-slug> <checkpoint-tag>
```

Never run without explicit approval: `git reset --hard`, `git clean`, `git stash`, `git commit --amend`, destructive `git restore` or `git checkout --`, interactive rebase, branch/tag deletion, or force push.

Explicit approval is also required before pushing, changing remotes, opening or merging pull requests, rebasing shared history, or deleting remote branches/tags.

## Completion Report

Report the task branch, base SHA, checkpoint tag, commits, files and changed-line totals, tests/checks, remaining uncommitted or unrelated changes, and exact per-commit rollback commands. Do not claim completion when required checks failed or were not run.
