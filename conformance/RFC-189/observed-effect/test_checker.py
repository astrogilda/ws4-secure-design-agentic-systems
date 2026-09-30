"""Regressions for the checker and the harness. Run: python -m unittest test_checker"""

from __future__ import annotations

import copy
import json
import os
import unittest
from typing import Any
from unittest.mock import patch

import checker
import run

HERE = os.path.dirname(os.path.abspath(__file__))


def load(case_id: str) -> dict[str, Any]:
    with open(os.path.join(HERE, "cases", f"{case_id}.json"), encoding="utf-8") as fh:
        case: dict[str, Any] = json.load(fh)
    return case


class Harness(unittest.TestCase):
    def test_every_committed_case_matches(self) -> None:
        self.assertEqual(run.main(), 0)

    def test_expectation_never_reaches_the_checker(self) -> None:
        built = run.build_input(load("RFC189-OE-03-NE-NAMED-GAP"))
        self.assertNotIn("expected_if_adopted", json.dumps(sorted(built)))
        self.assertEqual(set(built), {"property", "evidence", "context"})

    def test_a_tampered_expectation_is_reported_not_repaired(self) -> None:
        case = load("RFC189-OE-03-NE-NAMED-GAP")
        got = run.outcome(run.build_input(case))
        case["expected_if_adopted"] = {"verdict": "pass", "unmet_obligation": None}
        self.assertNotEqual(got, case["expected_if_adopted"])

    def test_a_pinned_hash_mismatch_refuses(self) -> None:
        case = load("RFC189-OE-01-PASS")
        case["checker_input"]["evidence"]["observed_effect"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            run.build_input(case)

    def test_a_record_absent_from_the_pinned_release_refuses(self) -> None:
        case = load("RFC189-OE-01-PASS")
        case["checker_input"]["evidence"]["observed_effect"]["vector"] = (
            "v0000000000000000"
        )
        with self.assertRaises(FileNotFoundError):
            run.build_input(case)

    def test_a_verdict_without_its_evaluation_is_not_graded(self) -> None:
        inp = run.build_input(load("RFC189-OE-03-NE-NAMED-GAP"))
        detached = {
            "verdict": "not_established",
            "unmet_obligation": "observation_coverage",
            "evaluation": {},
        }
        with patch.object(checker, "evaluate", return_value=detached):
            with self.assertRaisesRegex(ValueError, "not bound"):
                run.outcome(inp)


class Checker(unittest.TestCase):
    def base(self) -> dict[str, Any]:
        return run.build_input(load("RFC189-OE-01-PASS"))

    def test_missing_claim_ref_is_an_input_error_not_a_verdict(self) -> None:
        inp = self.base()
        del inp["context"]["claim_ref"]
        with self.assertRaises(checker.CandidateInputError):
            checker.evaluate(inp)

    def test_missing_observer_key_is_an_input_error_not_a_verdict(self) -> None:
        inp = self.base()
        del inp["context"]["observer_public_key"]
        with self.assertRaises(checker.CandidateInputError):
            checker.evaluate(inp)

    def test_empty_property_scope_is_an_input_error(self) -> None:
        inp = self.base()
        inp["property"]["scope"] = []
        with self.assertRaises(checker.CandidateInputError):
            checker.evaluate(inp)

    def test_a_record_signed_under_another_key_fails_the_vantage_claim(self) -> None:
        inp = self.base()
        inp["context"]["observer_public_key"] = (
            "763929ab5e25073572c6c63a261bc5b375a5b66f1cfe26cafe36885402d69632"
        )
        got = checker.evaluate(inp)
        # The observer's prior commitment is the member that carries the vantage
        # claim, and it is the first thing that fails to verify under the wrong key.
        self.assertEqual(got["verdict"], "not_established")
        self.assertEqual(got["unmet_obligation"], checker.OBSERVATION_VANTAGE)
        self.assertIn("commitment-signature-invalid", got["reason"])

    def test_unparseable_bytes_are_malformed_evidence(self) -> None:
        inp = self.base()
        inp["evidence"]["envelope"] = b"{not json"
        with self.assertRaises(checker.MalformedEvidence):
            checker.evaluate(inp)

    def test_not_established_always_names_an_obligation(self) -> None:
        for name in sorted(os.listdir(os.path.join(HERE, "cases"))):
            case = load(name.removesuffix(".json"))
            got = run.outcome(run.build_input(case))
            if got["verdict"] == "not_established":
                self.assertTrue(got["unmet_obligation"], name)

    def test_the_gap_decides_only_the_claims_it_touches(self) -> None:
        wide = run.build_input(load("RFC189-OE-03-NE-NAMED-GAP"))
        narrow = copy.deepcopy(wide)
        narrow["property"]["scope"] = ["/srv/app/src/"]
        vendor = copy.deepcopy(wide)
        vendor["property"]["scope"] = ["/srv/app/vendor/lib/"]
        self.assertEqual(checker.evaluate(wide)["verdict"], "not_established")
        self.assertEqual(checker.evaluate(narrow)["verdict"], "pass")
        self.assertEqual(checker.evaluate(vendor)["verdict"], "not_established")

    def test_equal_verdicts_keep_distinct_evaluations(self) -> None:
        first_input = run.build_input(load("RFC189-OE-03-NE-NAMED-GAP"))
        second_input = copy.deepcopy(first_input)
        second_input["property"]["scope"] = ["/srv/app/vendor/"]
        third_input = copy.deepcopy(first_input)
        third_input["context"]["claim_ref"] = "another-interval"
        first = checker.evaluate(first_input)
        second = checker.evaluate(second_input)
        third = checker.evaluate(third_input)
        self.assertEqual(first["verdict"], second["verdict"])
        self.assertEqual(first["unmet_obligation"], second["unmet_obligation"])
        self.assertEqual(first["verdict"], third["verdict"])
        self.assertEqual(first["unmet_obligation"], third["unmet_obligation"])
        self.assertNotEqual(first["evaluation"], second["evaluation"])
        self.assertNotEqual(first["evaluation"], third["evaluation"])
        self.assertEqual(first["evaluation"]["property"]["scope"], ["/srv/app/"])
        self.assertEqual(
            first["evaluation"]["context"]["claim_ref"],
            first_input["context"]["claim_ref"],
        )
        first_input["property"]["scope"].append("/elsewhere/")
        self.assertEqual(first["evaluation"]["property"]["scope"], ["/srv/app/"])

    def test_no_write_visibility_cannot_establish_absence(self) -> None:
        inp = self.base()
        del inp["context"]["producer_capability"]
        got = checker.evaluate(inp)
        self.assertEqual(got["verdict"], "not_established")
        self.assertEqual(
            got["unmet_obligation"], checker.PRODUCER_CAPABILITY_COVERAGE
        )

    def test_narrower_write_visibility_cannot_cover_the_claim(self) -> None:
        inp = self.base()
        inp["context"]["producer_capability"]["visible_write_paths"] = [
            "/srv/app/src/"
        ]
        got = checker.evaluate(inp)
        self.assertEqual(got["verdict"], "not_established")
        self.assertEqual(
            got["unmet_obligation"], checker.PRODUCER_CAPABILITY_COVERAGE
        )

    def test_invalid_write_visibility_is_a_processing_error(self) -> None:
        inp = self.base()
        inp["context"]["producer_capability"]["visible_write_paths"] = "*"
        with self.assertRaisesRegex(
            checker.CandidateInputError, "visible_write_paths must be a list"
        ):
            checker.evaluate(inp)

    def test_observed_write_can_fail_without_full_visibility(self) -> None:
        inp = run.build_input(load("RFC189-OE-05-FAIL-WITNESS-DESPITE-GAP"))
        del inp["context"]["producer_capability"]
        self.assertEqual(checker.evaluate(inp)["verdict"], "fail")

    def test_result_keeps_a_copy_of_capability_context(self) -> None:
        inp = self.base()
        got = checker.evaluate(inp)
        inp["context"]["producer_capability"]["visible_write_paths"].append(
            "/other/"
        )
        self.assertEqual(
            got["evaluation"]["context"]["producer_capability"][
                "visible_write_paths"
            ],
            ["/srv/app/"],
        )


if __name__ == "__main__":
    unittest.main()
