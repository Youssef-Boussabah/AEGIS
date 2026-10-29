"""Independent hidden behavioral test suite (``aegis.lab.hidden-suite.v1``).

Phase 4. A suite is a scorer-side file. It must never enter an attacker
workspace, a model prompt, a candidate worker or a retry. The manifest's
``scoring.hidden_test_suite_sha256`` is SHA-256 over the **exact suite file
bytes**, so the whole archive (all inputs and expectations) is bound, not a
small guessable answer.

Contents:

- ``interface``: the trial's ``scoring.expected_interface``; it must be inside
  ``aegis.lab.c-abi.scalar-u32.v1`` and every case must have its arity.
- ``reference``: how the expectations were produced. They are **frozen
  reference outputs**: computed once from a trusted reference implementation,
  identified by digest, and never derived from, or adjusted to, any candidate.
- ``cases``: ``c0001``, ``c0002``, ... in order (opaque by construction: an id
  cannot encode inputs), each with ``arguments`` and the ``expected`` value.

Every case is required: the ``all_hidden_tests_pass`` rule needs every case to
complete and match. Two cases with the same arguments are rejected. With equal
expectations they are redundant (``duplicate_case_arguments``); with different
expectations no deterministic function can pass both
(``contradictory_expectations``), which reveals an incorrect reference.

``audit_suite`` re-checks frozen expectations against a trusted reference
callable supplied by the suite author (for example a Python model of the
reference). It is a self-check for suite authors, not part of scoring, and it
never calls candidate code.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictInt, model_validator
from pydantic_core import PydanticCustomError

from .c_abi import ABI_VERSION, MAX_ARITY, U32_MAX, InterfaceError, parse_interface
from .manifest import Hash, Identifier, ToolIdentity, TrialId
from .safe_io import LoadError, parse_strict_json, read_regular_file

HIDDEN_SUITE_SCHEMA = "aegis.lab.hidden-suite.v1"
MAX_SUITE_BYTES = 4 * 1024 * 1024
MAX_SUITE_CASES = 4096

SUITE_ERROR_TYPES = frozenset({
    "aegis_case_ids_not_sequential",
    "aegis_arity_mismatch",
    "aegis_interface_not_supported",
    "aegis_duplicate_case_arguments",
    "aegis_contradictory_expectations",
})

U32 = Annotated[StrictInt, Field(ge=0, le=U32_MAX)]


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SuiteReference(StrictRecord):
    """Provenance of the frozen expectations. A declaration by the suite author, not proof."""

    method: Literal["frozen_reference_outputs"]
    reference_implementation_sha256: Hash
    generator: ToolIdentity
    frozen_at: AwareDatetime


class HiddenCase(StrictRecord):
    case_id: Annotated[str, Field(pattern=r"^c[0-9]{4}$")]
    arguments: Annotated[tuple[U32, ...], Field(max_length=MAX_ARITY)]
    expected: U32


class HiddenSuite(StrictRecord):
    schema_version: Literal["aegis.lab.hidden-suite.v1"] = HIDDEN_SUITE_SCHEMA
    suite_id: TrialId
    abi: Literal["aegis.lab.c-abi.scalar-u32.v1"] = ABI_VERSION
    interface: Identifier
    reference: SuiteReference
    cases: Annotated[tuple[HiddenCase, ...], Field(min_length=1, max_length=MAX_SUITE_CASES)]

    @model_validator(mode="after")
    def _cases(self) -> HiddenSuite:
        try:
            arity = parse_interface(self.interface).arity
        except InterfaceError:
            raise PydanticCustomError("aegis_interface_not_supported",
                                      "the interface is outside the suite ABI") from None
        seen: dict[tuple[int, ...], int] = {}
        for index, case in enumerate(self.cases, start=1):
            if case.case_id != f"c{index:04d}":
                raise PydanticCustomError("aegis_case_ids_not_sequential", "case ids must be c0001, c0002, ...")
            if len(case.arguments) != arity:
                raise PydanticCustomError("aegis_arity_mismatch", "a case does not match the interface arity")
            if case.arguments in seen:
                if seen[case.arguments] != case.expected:
                    raise PydanticCustomError("aegis_contradictory_expectations",
                                              "two cases with equal arguments expect different results")
                raise PydanticCustomError("aegis_duplicate_case_arguments", "two cases have equal arguments")
            seen[case.arguments] = case.expected
        return self

    @property
    def arity(self) -> int:
        return parse_interface(self.interface).arity


def parse_hidden_suite(data: bytes) -> HiddenSuite:
    """Parse untrusted suite bytes. Raises ``LoadError`` or ``pydantic.ValidationError``."""
    if len(data) > MAX_SUITE_BYTES:
        raise LoadError("too_large")
    parse_strict_json(data)  # duplicate keys, NaN and invalid UTF-8 are rejected first
    return HiddenSuite.model_validate_json(data)


def load_hidden_suite(path) -> tuple[HiddenSuite, bytes]:
    data = read_regular_file(path, MAX_SUITE_BYTES)
    return parse_hidden_suite(data), data


def suite_sha256(data: bytes) -> str:
    """The value to declare as ``scoring.hidden_test_suite_sha256``: SHA-256 of the file bytes."""
    return hashlib.sha256(data).hexdigest()


def serialize_suite(suite: HiddenSuite) -> bytes:
    """Stable bytes for a suite (sorted keys, ASCII). Any byte change changes its digest."""
    return (json.dumps(suite.model_dump(mode="json"), indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode()


def build_hidden_suite(*, suite_id: str, interface: str, reference: SuiteReference,
                       argument_sets: list[tuple[int, ...]],
                       reference_function: Callable[..., int]) -> HiddenSuite:
    """Freeze expectations from a *trusted* reference callable. Never pass candidate code."""
    cases = []
    for index, arguments in enumerate(argument_sets, start=1):
        cases.append(HiddenCase(case_id=f"c{index:04d}", arguments=tuple(arguments),
                                expected=reference_function(*arguments)))
    return HiddenSuite(suite_id=suite_id, interface=interface, reference=reference, cases=tuple(cases))


def audit_suite(suite: HiddenSuite, reference_function: Callable[..., int]) -> tuple[str, ...]:
    """Case ids whose frozen expectation differs from a trusted reference callable."""
    mismatched = []
    for case in suite.cases:
        value = reference_function(*case.arguments)
        if type(value) is not int or value != case.expected:
            mismatched.append(case.case_id)
    return tuple(mismatched)
