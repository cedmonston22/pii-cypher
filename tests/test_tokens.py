"""Token format, uniqueness, and batch-wide assignment."""

from core.extract import Line
from core.tokens import ALPHABET, LENGTH, PREFIX, TOKEN_RE, assign, find_tokens, mint_token


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
