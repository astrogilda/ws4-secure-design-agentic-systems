"""Grade every committed case against checker.evaluate. Read-only.

For each case file: resolve the named Observed Effect record to its bytes, check
the bytes against the pinned SHA-256, build the checker input from
`checker_input` alone, evaluate, and compare the outcome with
`expected_if_adopted`. The expectation never reaches the checker. Nothing is
written; any mismatch, missing record or hash mismatch exits non-zero.

Records come only from the installed `agent-evidence-vectors` package: the
published corpus at the release requirements.txt pins by hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from importlib import resources
from typing import Any

import checker

HERE = os.path.dirname(os.path.abspath(__file__))
FAILURES = (
    checker.MalformedEvidence,
    checker.UnsupportedVerification,
    checker.CandidateInputError,
)


def record_bytes(vector: str) -> bytes:
    published = resources.files("agent_evidence_vectors").joinpath(
        "corpora", "vectors-observed-effect", "statements", f"{vector}.json"
    )
    if not published.is_file():
        raise FileNotFoundError(f"record {vector} is not in the installed corpus")
    return published.read_bytes()


def build_input(case: dict[str, Any]) -> dict[str, Any]:
    spec = case["checker_input"]
    ref = spec["evidence"]["observed_effect"]
    raw = record_bytes(ref["vector"])
    digest = hashlib.sha256(raw).hexdigest()
    if digest != ref["sha256"]:
        raise ValueError(
            f"record {ref['vector']} hashes to {digest}, case pins {ref['sha256']}"
        )
    return {
        "property": spec["property"],
        "evidence": {"envelope": raw},
        "context": {
            "claim_ref": spec["context"]["claim_ref"],
            "observer_public_key": spec["context"]["observer_public_key"],
            "anchored_commitment_digest": spec["context"].get(
                "anchored_commitment_digest"
            ),
            "producer_capability": spec["context"].get("producer_capability"),
        },
    }


def outcome(checker_input: dict[str, Any]) -> dict[str, Any]:
    try:
        result = checker.evaluate(checker_input)
    except FAILURES as exc:
        out: dict[str, Any] = {
            "verdict": None,
            "processing_failure": type(exc).__name__,
        }
        if isinstance(exc, checker.MalformedEvidence):
            out["codes"] = exc.codes
        return out
    prop = checker_input["property"]
    ctx = checker_input["context"]
    expected_evaluation = {
        "property": {"name": prop["name"], "scope": prop["scope"]},
        "context": {
            "claim_ref": ctx["claim_ref"],
            "observer_public_key": ctx["observer_public_key"],
            "anchored_commitment_digest": ctx.get("anchored_commitment_digest"),
            "producer_capability": ctx.get("producer_capability"),
        },
    }
    if result.get("evaluation") != expected_evaluation:
        raise ValueError("checker result is not bound to the evaluated property and context")
    return {
        "verdict": result["verdict"],
        "unmet_obligation": result["unmet_obligation"],
    }


def main() -> int:
    case_dir = os.path.join(HERE, "cases")
    names = sorted(n for n in os.listdir(case_dir) if n.endswith(".json"))
    if not names:
        print("no cases found", file=sys.stderr)
        return 2
    mismatches = 0
    for name in names:
        with open(os.path.join(case_dir, name), encoding="utf-8") as fh:
            case = json.load(fh)
        try:
            got = outcome(build_input(case))
        except (OSError, ValueError, KeyError) as exc:
            print(f"ERROR {case.get('id', name)}: {exc}")
            mismatches += 1
            continue
        want = case["expected_if_adopted"]
        ok = got == want
        mismatches += not ok
        status = "ok  " if ok else "FAIL"
        print(f"{status} {case['id']}: {json.dumps(got, sort_keys=True)}")
        if not ok:
            print(f"     expected {json.dumps(want, sort_keys=True)}")
    print(f"{len(names) - mismatches} of {len(names)} cases match their expectation")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
