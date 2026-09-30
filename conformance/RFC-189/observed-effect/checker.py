"""Checker for the RFC-189 verdict rule over Observed Effect records.

The rule under test is the one converged on in issue #189 (see ../README.md for
the clause list and the comment each clause comes from). It is a candidate rule
until RFC-189 is approved, and every case this checker grades is labelled
`candidate_against_proposed`.

The evidence is a signed Observed Effect statement (a DSSE envelope carrying an
in-toto Statement): an observer records a mutation interval, the path scope it
covered, the gaps it did not cover, and every write it saw. The checker tests
whether the vantage is independent. Admission of the record is delegated to
the reference verifier published as the `agent-evidence-vectors` package, so
this file decides only what the RFC-189 rule decides: what the admitted record
lets a verifier conclude about a property.

Property implemented: `no_write_in_scope`, a negative quantified over a path
scope and one observed interval: "no write occurred under these paths during
this interval."

Three outcome axes are kept apart, as the #189 thread requires:

- The property verdict is exactly `pass`, `fail` or `not_established`.
- A record the reference verifier refuses as malformed, an unsupported property
  and a structurally invalid candidate input are processing failures. They
  raise; they never become `not_established`.
- `not_established` always names the unmet obligation.
- Each verdict carries the property and context used to reach it.

Checker input is {property, evidence, context}. Context may carry an expected
prior commitment and producer capability established outside the record for
this invocation.
The harness expectation is held outside the checker input and compared by
run.py afterwards.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from agent_evidence_vectors import observedeffect

PREDICATE_TYPE = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect"
)
SUPPORTED_PROPERTIES = frozenset({"no_write_in_scope"})

# Obligation names. `observation_coverage` is the name the #189 thread already
# uses. `observation_vantage` is the agent-evidence-vocabulary term for who
# observed: a record the observed party could have written or suppressed is not
# independent evidence of anything it asserts.
OBSERVATION_COVERAGE = "observation_coverage"
OBSERVATION_VANTAGE = "observation_vantage"
OBSERVATION_SCOPE = "observation_scope"
ADMISSIBLE_OBSERVATION = "admissible_observation"
INVOCATION_BINDING = "invocation_binding"
PRODUCER_CAPABILITY_COVERAGE = "producer_capability_coverage"

# A record the reference verifier finds coherent but whose own rules refuse its
# claim (verdict `invalid`) is not a processing failure: the verification ran.
# It cannot support pass or fail, so the property is not_established, and the
# refusal code names which premise the record failed to carry.
INVALID_CODE_OBLIGATION = {
    "authoritative-vantage-not-independent": OBSERVATION_VANTAGE,
    "commitment-keyid-not-disjoint": OBSERVATION_VANTAGE,
    "commitment-not-prior": OBSERVATION_VANTAGE,
    "commitment-signature-invalid": OBSERVATION_VANTAGE,
    "authoritative-coverage-incomplete": OBSERVATION_COVERAGE,
    "authoritative-empty-path-scope": OBSERVATION_SCOPE,
    "authoritative-without-observed-rows": OBSERVATION_SCOPE,
}


class MalformedEvidence(Exception):
    """The reference verifier refused the record as malformed. Not a verdict."""

    def __init__(self, codes: list[str]) -> None:
        super().__init__(", ".join(codes))
        self.codes = codes


class UnsupportedVerification(Exception):
    """This checker does not implement the requested property. Not a verdict."""


class CandidateInputError(ValueError):
    """The candidate input is structurally invalid. Not a verdict."""


def _validate(checker_input: Any) -> None:
    """Structural gate, run once before any inference, so no inference branch
    decides what an absent key means."""
    if not isinstance(checker_input, dict):
        raise CandidateInputError("checker input must be an object")
    for key in ("property", "evidence", "context"):
        if not isinstance(checker_input.get(key), dict):
            raise CandidateInputError(f"checker input requires object {key!r}")
    prop = checker_input["property"]
    if not isinstance(prop.get("name"), str) or not prop["name"]:
        raise CandidateInputError("property requires a non-empty string name")
    scope = prop.get("scope")
    if (
        not isinstance(scope, list)
        or not scope
        or not all(isinstance(p, str) and p.startswith("/") for p in scope)
    ):
        raise CandidateInputError(
            "property.scope must be a non-empty list of absolute path prefixes"
        )
    evidence = checker_input["evidence"]
    if not isinstance(evidence.get("envelope"), bytes):
        raise CandidateInputError("evidence.envelope must be the record's bytes")
    ctx = checker_input["context"]
    if not isinstance(ctx.get("claim_ref"), str) or not ctx["claim_ref"]:
        raise CandidateInputError(
            "context requires claim_ref: coverage is bound to one claim instance, "
            "so the evaluated one must be named"
        )
    key = ctx.get("observer_public_key")
    if not isinstance(key, str) or len(key) != 64:
        raise CandidateInputError(
            "context requires the observer's Ed25519 public key as 64 hex characters, "
            "anchored out of band and never read from the record"
        )
    expected_commitment = ctx.get("anchored_commitment_digest")
    if expected_commitment is not None and (
        not isinstance(expected_commitment, str)
        or len(expected_commitment) != 64
        or any(ch not in "0123456789abcdef" for ch in expected_commitment)
    ):
        raise CandidateInputError(
            "context.anchored_commitment_digest must be a 64-character lowercase "
            "hex digest when supplied"
        )
    capability = ctx.get("producer_capability")
    if capability is not None:
        if not isinstance(capability, dict):
            raise CandidateInputError("context.producer_capability must be an object")
        if not isinstance(capability.get("claim_ref"), str) or not capability["claim_ref"]:
            raise CandidateInputError(
                "context.producer_capability.claim_ref must be a non-empty string"
            )
        paths = capability.get("visible_write_paths")
        if not isinstance(paths, list) or not all(
            isinstance(p, str) and p.startswith("/") for p in paths
        ):
            raise CandidateInputError(
                "context.producer_capability.visible_write_paths must be a list "
                "of absolute path prefixes"
            )


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(
        prefix if prefix.endswith("/") else prefix + "/"
    )


def _overlaps(a: str, b: str) -> bool:
    return _under(a, b) or _under(b, a)


def _not_established(obligation: str, reason: str) -> dict[str, Any]:
    return {
        "verdict": "not_established",
        "unmet_obligation": obligation,
        "reason": reason,
    }


def _evaluate(checker_input: dict[str, Any]) -> dict[str, Any]:
    _validate(checker_input)
    prop = checker_input["property"]
    ctx = checker_input["context"]
    raw = checker_input["evidence"]["envelope"]

    if prop["name"] not in SUPPORTED_PROPERTIES:
        raise UnsupportedVerification(
            f"property {prop['name']!r} is not implemented by this checker; "
            "no verification of the property was performed"
        )

    policy = observedeffect.Policy(
        predicate_type=PREDICATE_TYPE, observer_public_key=ctx["observer_public_key"]
    )
    report = observedeffect.verify(raw, policy)
    if report.verdict == "malformed":
        raise MalformedEvidence(report.codes)
    if report.verdict == "invalid":
        code = report.codes[0] if report.codes else ""
        return _not_established(
            INVALID_CODE_OBLIGATION.get(code, ADMISSIBLE_OBSERVATION),
            f"the reference verifier refused the record ({code}); a refused record "
            "supports neither pass nor fail",
        )
    if report.verdict != "valid":
        raise CandidateInputError(f"unexpected admission verdict {report.verdict!r}")

    pred = json.loads(base64.b64decode(json.loads(raw)["payload"]))["predicate"]
    observation = pred["observation"]
    scope: list[str] = prop["scope"]

    # Per-claim binding. Coverage established for one interval cannot establish
    # completeness for another.
    if pred["intervalId"] != ctx["claim_ref"]:
        return _not_established(
            OBSERVATION_COVERAGE,
            f"the record covers interval {pred['intervalId']!r}, not the evaluated "
            f"claim {ctx['claim_ref']!r}",
        )
    # The property may not be wider than what was observed.
    uncovered = [p for p in scope if not any(_under(p, s) for s in pred["pathScope"])]
    if uncovered:
        return _not_established(
            OBSERVATION_COVERAGE,
            f"the property scope {uncovered} lies outside the observed pathScope "
            f"{pred['pathScope']}",
        )
    # Who observed. A record at the observed party's own vantage, or at a peer
    # layer it could route around, is not independent evidence in either
    # direction.
    if observation["vantage"] != "below-observed":
        return _not_established(
            OBSERVATION_VANTAGE,
            f"observation vantage is {observation['vantage']!r}; only a vantage the "
            "observed party cannot address is independent evidence",
        )
    # The signed interval identifier authenticates what the observer asserted,
    # but does not join that interval to the invocation under evaluation. The
    # expected prior commitment must come from trusted context independent of
    # this record (for example, an external pre-interval witness). These
    # synthetic cases stipulate that context; they do not prove its provenance.
    expected_commitment = ctx.get("anchored_commitment_digest")
    prior = observation.get("priorCommitment")
    actual_commitment = prior.get("commitmentDigest") if isinstance(prior, dict) else None
    if not expected_commitment or actual_commitment != expected_commitment:
        return _not_established(
            INVOCATION_BINDING,
            "the record's prior commitment is not independently bound to the "
            "evaluated invocation",
        )
    # Asymmetry: one observed write inside the property scope settles fail on
    # its own, with no completeness premise.
    witnesses = [
        w["path"] for w in pred["writes"] if any(_under(w["path"], s) for s in scope)
    ]
    if witnesses:
        return {
            "verdict": "fail",
            "unmet_obligation": None,
            "reason": f"write(s) observed inside the property scope: {witnesses}",
        }
    # A negative needs complete coverage of the property scope for the interval.
    # A gap the record names is a gap it did not watch.
    coverage = observation["coverage"]
    blind = (
        []
        if coverage["scopeComplete"]
        else [g for g in coverage["gaps"] if any(_overlaps(g, s) for s in scope)]
    )
    if blind:
        return _not_established(
            OBSERVATION_COVERAGE,
            f"the record names unobserved path(s) inside the property scope: {blind}",
        )
    capability = ctx.get("producer_capability")
    if capability is None:
        return _not_established(
            PRODUCER_CAPABILITY_COVERAGE,
            "no write visibility was established for the evaluated invocation",
        )
    if capability["claim_ref"] != ctx["claim_ref"]:
        return _not_established(
            PRODUCER_CAPABILITY_COVERAGE,
            "write visibility was established for a different invocation",
        )
    if any(
        not any(_under(p, visible) for visible in capability["visible_write_paths"])
        for p in scope
    ):
        return _not_established(
            PRODUCER_CAPABILITY_COVERAGE,
            "write visibility does not cover the evaluated path scope",
        )
    return {
        "verdict": "pass",
        "unmet_obligation": None,
        "reason": "no write observed inside the property scope, with write visibility "
        "and complete coverage for the interval from an independent vantage",
    }


def evaluate(checker_input: dict[str, Any]) -> dict[str, Any]:
    result = _evaluate(checker_input)
    prop = checker_input["property"]
    ctx = checker_input["context"]
    result["evaluation"] = {
        "property": {"name": prop["name"], "scope": list(prop["scope"])},
        "context": {
            "claim_ref": ctx["claim_ref"],
            "observer_public_key": ctx["observer_public_key"],
            "anchored_commitment_digest": ctx.get("anchored_commitment_digest"),
            "producer_capability": (
                {
                    "claim_ref": ctx["producer_capability"]["claim_ref"],
                    "visible_write_paths": list(
                        ctx["producer_capability"]["visible_write_paths"]
                    ),
                }
                if ctx.get("producer_capability") is not None
                else None
            ),
        },
    }
    return result
