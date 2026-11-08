# Vendored: iab-agentic-primitives

This directory is the Web Bot Auth library both agents use, pinned at one
commit and copied unchanged: the library's `pyproject.toml`, `README.md`,
`LICENSE`, and `src/` at that commit, nothing else.

| | |
| :--- | :--- |
| Source repository | [`KonstantinMirin/iab-agentic-primitives-wba`](https://github.com/KonstantinMirin/iab-agentic-primitives-wba) |
| Branch | `refactor/wba-architecture` |
| Commit | `4cabcbe9b4c2e04b116ccdca85b44d4587bcf659` |
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
