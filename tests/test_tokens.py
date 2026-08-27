"""Token format, uniqueness, and batch-wide assignment."""

from core.extract import Line
import pytest

from core.tokens import (
    ALPHABET,
    LENGTH,
    MAX_REVEAL_DIGITS,
    PREFIX,
    SUFFIX_SEP,
    TOKEN_RE,
    assign,
    digits_of,
    display,
    display_candidates,
    find_tokens,
    mint_token,
)


def test_token_format():
    token = mint_token()
    assert token.startswith(PREFIX)
    assert len(token) == len(PREFIX) + LENGTH
    assert TOKEN_RE.fullmatch(token)


def test_alphabet_excludes_ambiguous_characters():
    assert len(ALPHABET) == 32
    for char in "01OIl":
        assert char not in ALPHABET


def test_no_collisions_over_many_draws():
    tokens = set()
    for _ in range(20_000):
        token = mint_token(tokens)
        assert token not in tokens
        tokens.add(token)
    assert len(tokens) == 20_000


def test_token_is_not_derived_from_any_value():
    assert mint_token() != mint_token()


def test_assign_reuses_tokens_across_documents():
    """The batch-level token map is what makes one value one token everywhere."""
    token_map: dict[str, str] = {}
    assign(["000-00-0000", "456 SAMPLE AVE"], token_map)
    first = token_map["000-00-0000"]

    assign(["000-00-0000", "123 EXAMPLE LANE"], token_map)
    assert token_map["000-00-0000"] == first
    assert len(token_map) == 3
    assert len(set(token_map.values())) == 3


def _line(text: str) -> Line:
    return Line(text=text, x0=0, top=0, x1=10, bottom=10, page=1)


def test_find_tokens_reads_them_back():
    token = mint_token()
    pages = [[_line(f"SSN {token} on file"), _line("no token here")]]
    assert find_tokens(pages) == [token]


def test_find_tokens_deduplicates():
    token = mint_token()
    assert find_tokens([[_line(token), _line(token)]]) == [token]


def test_find_tokens_ignores_near_misses():
    pages = [[_line("PII-0000000O"), _line("PII-SHORT"), _line("XPII-ABCDEFGH")]]
    assert find_tokens(pages) == []


# --------------------------------------------------------------------------
# partial disclosure: the on-page form of a token
# --------------------------------------------------------------------------


def test_a_revealed_token_is_still_discoverable():
    """The whole restore path hangs off find_tokens seeing the bare token."""
    token = mint_token()
    pages = [[_line(f"SSN {display(token, '512-44-8890', 6)} on file")]]
    assert find_tokens(pages) == [token]


def test_the_separator_is_load_bearing():
    """Without a non-word character the trailing boundary in TOKEN_RE fails.

    A token nobody can find makes the document unidentifiable: identify_job
    reports no tokens, match_document returns None, and every restore comes back
    unmatched. The failure is total and silent, so pin it deliberately.
    """
    token = mint_token()
    assert find_tokens([[_line(f"{token}{SUFFIX_SEP}8890")]]) == [token]
    assert find_tokens([[_line(f"{token}8890")]]) == [], "bare digits kill the boundary"
    assert not SUFFIX_SEP.isalnum() and SUFFIX_SEP != "_"


@pytest.mark.parametrize("n", range(1, MAX_REVEAL_DIGITS + 1))
def test_display_shows_exactly_n_digits(n):
    token = mint_token()
    out = display(token, "512-44-8890", n)
    assert out == f"{token}{SUFFIX_SEP}{'512448890'[-n:]}"
    assert len(digits_of(out.split(SUFFIX_SEP)[-1])) == n


def test_display_reveals_nothing_by_default():
    token = mint_token()
    assert display(token, "512-44-8890") == token
    assert display(token, "512-44-8890", 0) == token


def test_candidates_are_ordered_longest_first():
    """A six-digit tail matched as a four-digit one strands two digits."""
    token = mint_token()
    candidates = display_candidates(token, "512-44-8890")

    assert candidates[0] == display(token, "512-44-8890", MAX_REVEAL_DIGITS)
    assert candidates[-1] == token, "the bare token is the last resort"
    assert candidates == sorted(candidates, key=len, reverse=True)


def test_candidates_cover_every_reachable_form():
    """Restore is not told the policy, so it must be able to guess every form."""
    token, value = mint_token(), "512-44-8890"
    candidates = display_candidates(token, value)

    for n in range(0, MAX_REVEAL_DIGITS + 1):
        assert display(token, value, n) in candidates


def test_digits_of_ignores_formatting():
    assert digits_of("512-44-8890") == "512448890"
    assert digits_of("45-1234567") == "451234567"
    assert digits_of("no digits here") == ""
