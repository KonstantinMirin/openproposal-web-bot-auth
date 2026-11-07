"""Proof that each committed ast-grep rule fires on a planted violation, and only there.

`make guards` runs the rules over the tree. A rule that is misspelled, or whose
`files:` glob matches nothing, reads exactly like a rule nobody violates, so
each one is proven here: the committed rule file is copied into a temporary
tree, a violation is planted at a path the rule covers, and the real ast-grep
must report it at the planted line. A clean twin of the snippet must report
nothing, so that no rule can match everything.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tests._tools import run, tool

REPO = Path(__file__).resolve().parent.parent
RULES = REPO / ".ast-grep" / "rules"
AST_GREP = tool("ast-grep")

# (rule id, planted path, violation, clean twin). The violation's last line is the
# one the rule must report.
CASES = (
    (
        "identity-built-only-by-the-boundary",
        "seller/app.py",
        "from .caller import Principal\n\n"
        "p = Principal(id='x', kind='buyer', legal_name='X', domain='x.example')\n",
        "from .caller import Principal\n\n\ndef name(p: Principal) -> str:\n    return p.id\n",
    ),
    (
        "identity-built-only-by-the-boundary",
        "tests/test_planted.py",
        "from seller.caller import ResolvedCaller\n\nc = ResolvedCaller.model_validate({})\n",
        "from seller.caller import ResolvedCaller\n\n\ndef kind(c: ResolvedCaller) -> str:\n"
        "    return c.kind\n",
    ),
    (
        "identity-built-only-by-the-boundary",
        "seller/sqlite_store.py",
        "from .caller import BearerCredential\n\nb = BearerCredential(method='bearer')\n",
        "from .caller import BearerCredential\n\n\ndef m(b: BearerCredential) -> str:\n"
        "    return b.method\n",
    ),
    (
        "identity-never-amended",
        "seller/offers/acceptance.py",
        "def amend(caller):\n    return caller.model_copy(update={'principal': None})\n",
        "def keep(caller):\n    return caller.principal.id\n",
    ),
    (
        "boundary-never-downgrades",
        "seller/boundary.py",
        "async def resolve(verifier):\n    try:\n        await verifier.verify()\n"
        "    except Exception:\n        return None\n",
        "async def resolve(verifier):\n    try:\n        await verifier.verify()\n"
        "    except Exception as e:\n        raise Refused() from e\n",
    ),
    (
        "buyer-verifies-every-answer",
        "buyer/seller_client.py",
        "def auth(signer, verifier):\n    return WebBotAuth(signer, verifier)\n",
        "def auth(signer, verifier, origin):\n"
        "    return WebBotAuth(signer, verifier, expect=origin)\n",
    ),
    (
        "observers-read-through-the-read-models",
        "runner/observe.py",
        "def count(db):\n    return db.execute('SELECT COUNT(*) FROM assent')\n",
        "def count(records):\n    return len(records.entries('demo-wba-1'))\n",
    ),
    (
        "routes-take-no-request",
        "seller/http.py",
        "@api.post('/x')\nasync def x(caller: CallerDep, request: Request) -> None:\n    pass\n",
        "@api.post('/x')\nasync def x(caller: CallerDep, body: bytes) -> None:\n    pass\n",
    ),
    (
        "offers-are-credential-blind",
        "seller/offers/acceptance.py",
        "def gate(caller):\n    return caller.credential.method == 'bearer'\n",
        "def gate(caller):\n    return caller.principal.id == 'buyer-wba'\n",
    ),
    (
        "offers-are-credential-blind",
        "seller/offers/checks.py",
        "def peek(ctx):\n    return ctx.request.headers\n",
        "def peek(ctx):\n    return ctx.request.entry\n",
    ),
    (
        "credential-read-only-at-the-boundary",
        "seller/offers.py",
        "def peek(request):\n    return request.headers\n",
        "def peek(caller):\n    return caller.principal\n",
    ),
    (
        "credential-read-only-at-the-boundary",
        "shared/record.py",
        "FIELD = 'signature-input'\n",
        "FIELD = 'line_item_ids'\n",
    ),
)


def _scan(tree: Path, rule: str, path: str, source: str) -> list[int]:
    """The lines at which `rule` fires on `source` planted at `path` in a tree of its own."""
    (tree / ".ast-grep" / "rules").mkdir(parents=True, exist_ok=True)
    shutil.copy(RULES / f"{rule}.yml", tree / ".ast-grep" / "rules")
    (tree / "sgconfig.yml").write_text("ruleDirs:\n  - .ast-grep/rules\n")
    planted = tree / path
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text(source)
    scan = run([str(AST_GREP), "scan", "--config", "sgconfig.yml", "--json=compact"], cwd=tree)
    # 0 is clean, 1 is violations; anything else means the rule didn't run.
    assert scan.returncode in (0, 1), scan.stderr
    return [m["range"]["end"]["line"] + 1 for m in json.loads(scan.stdout or "[]")]


@pytest.mark.parametrize(("rule", "path", "bad", "good"), CASES, ids=[c[0] for c in CASES])
def test_rule_fires_on_the_violation_and_not_on_its_clean_twin(
    tmp_path: Path, rule: str, path: str, bad: str, good: str
) -> None:
    assert _scan(tmp_path / "bad", rule, path, bad) == [bad.count("\n")]
    assert _scan(tmp_path / "good", rule, path, good) == []


def test_only_cfbot_signs_without_verifying_the_answer(tmp_path: Path) -> None:
    """The rule's one exemption is the sign-only peer, buyer/cfbot.py, and nothing else."""
    sign_only = "def auth(signer):\n    return WebBotAuth(signer)\n"
    assert (
        _scan(tmp_path / "cfbot", "buyer-verifies-every-answer", "buyer/cfbot.py", sign_only) == []
    )
    assert _scan(tmp_path / "flow", "buyer-verifies-every-answer", "buyer/flow.py", sign_only) == [
        2
    ]


def test_every_committed_rule_has_a_proof() -> None:
    assert {c[0] for c in CASES} == {p.stem for p in RULES.glob("*.yml")}


def test_the_tree_holds_no_violation() -> None:
    scan = run([str(AST_GREP), "scan", "--config", "sgconfig.yml"], cwd=REPO)
    assert scan.returncode == 0, scan.stdout
