# Vendored: iab-agentic-primitives

This directory is the Web Bot Auth library both agents use, pinned at one
commit and copied unchanged: the library's `pyproject.toml`, `README.md`,
`LICENSE`, and `src/` at that commit, nothing else.

| | |
| :--- | :--- |
| Source repository | [`KonstantinMirin/iab-agentic-primitives`](https://github.com/KonstantinMirin/iab-agentic-primitives), the head of [IABTechLab/iab-agentic-primitives#4](https://github.com/IABTechLab/iab-agentic-primitives/pull/4) |
| Branch | `feat/web-bot-auth` |
| Commit | `3bcfb963bfa53a3c2fa598019dc8b052025620de` |
| Vendored on | 2026-11-08 |

`pyproject.toml` at the repository root installs it with a uv path source
(`vendor/iab-agentic-primitives`, editable), and the image build installs it
from this directory, so a fresh clone installs with no other checkout.

## Refresh

From the repository root, with a library checkout at `LIB` and the commit to
pin at `SHA`, run:

```bash
rm -rf vendor/iab-agentic-primitives/{pyproject.toml,README.md,LICENSE,src} && git -C "$LIB" archive "$SHA" pyproject.toml README.md LICENSE src | tar -x -C vendor/iab-agentic-primitives
```

Then update the commit, branch, and date above and in the README's library
section, and run `uv lock`.
