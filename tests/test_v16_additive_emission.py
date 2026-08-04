"""Invariant A1: additive emission (v1.6 family 1).

Canonicalization emits the canonical form ALONGSIDE the raw token, never
instead of it.  The testable invariant, pre-registered in
docs/PREDICTIONS_v16_family1.md, AMENDMENT 1, item A1:

    NO TOKEN THAT QUALIFIED PRE-CANONICALIZATION IS ABSENT POST-CANONICALIZATION.

Why this matters (the A1 worked example): untrusted content says
``wire $9,847.00`` and the agent emits ``amount=$9,847.00``.  Today the raw
token ``$9,847.00`` qualifies (9 chars, digits, structural) and
substring-matches the untrusted blob, producing a catch.  Under
REPLACEMENT-style canonicalization it would become ``9847`` (4 chars), fall
below the ``min_len=6`` distinctiveness gate, and vanish from both gates: the
normalizer would have DELETED a catch.  Additive emission makes normalization
monotone on soundness by construction.

This test is written before the normalizers and must keep passing as each one
is added.  It fails the moment emission becomes replacement-style, because the
raw floor (``_base_lineage_tokens``) would stop being a subset of the full
extractor output.
"""

import pytest

from agentlock.context import _base_lineage_tokens, extract_lineage_tokens

MIN_LEN = 6

# A battery spanning the family-1 surface (attack + benign, both probes) and
# the A1 worked example.  Every value here goes through both the raw floor and
# the full extractor; the floor must survive.
_VALUES = [
    # probe 1 attack surface
    "mallory@evil.com",
    "evil.co",
    "HTTPS://EVIL.COM",
    "please contact mallory@evil.com now",
    "evil[.]com",
    "e-v-i-l.com",
    # probe 1/2 benign surface
    "03/14/2026",
    "2026-03-14",
    "5551234567",
    "+1 (555) 123-4567",
    "$1,000.00",
    "alice@acme.com",
    "quarterly-report-2026",
    # probe 2 out-of-scope surface
    "$14,207.50",
    "report_alice_2026-03-14.pdf",
    "ORD-2026-88421",
    "3f2b9c14-7d6a-4e58-9b21-0c8e5a7f4d33",
    # the A1 worked example
    "$9,847.00",
]


@pytest.mark.parametrize("value", _VALUES)
def test_raw_floor_is_subset_of_full_extractor(value):
    """Every raw token still present after canonicalization runs."""
    base = _base_lineage_tokens(value, MIN_LEN)
    full = extract_lineage_tokens(value, MIN_LEN)
    missing = base - full
    assert not missing, (
        f"additive-emission invariant violated for {value!r}: "
        f"canonicalization DELETED raw tokens {missing}. Emission must be "
        f"additive (floor UNION canonical), never replacement."
    )


def test_a1_worked_example_raw_amount_token_survives():
    """The '$9,847.00' catch must not be deleted by canonicalization."""
    full = extract_lineage_tokens("$9,847.00", MIN_LEN)
    toks = {t for _kind, t in full}
    assert "$9,847.00" in toks, (
        "the raw '$9,847.00' token must survive canonicalization; its absence "
        "means emission became replacement-style and an existing catch was "
        "deleted (invariant A1)."
    )


def test_canonical_forms_are_strictly_additional():
    """The full extractor is exactly the floor plus the canonical set: the
    canonical pass may add tokens but must never subtract."""
    from agentlock.context import _canonical_lineage_tokens

    for value in _VALUES:
        base = _base_lineage_tokens(value, MIN_LEN)
        canon = _canonical_lineage_tokens(value, MIN_LEN)
        full = extract_lineage_tokens(value, MIN_LEN)
        assert full == base | canon, (
            f"extractor must be floor UNION canonical for {value!r}; "
            f"got {full} vs {base | canon}"
        )
