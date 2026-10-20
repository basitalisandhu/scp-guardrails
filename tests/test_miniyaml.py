"""The standard-library YAML reader: scalar typing, block scalars, collections, anchors and errors."""

import math

import pytest

from scp_guardrails._miniyaml import YAMLError, load, load_all


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a: 1", 1),
        ("a: -7", -7),
        ("a: +2", 2),
        ("a: 1_000", 1000),
        ("a: 0x1F", 31),
        ("a: 0o17", 15),
        ("a: 1.5", 1.5),
        ("a: 1.5e3", 1500.0),
        ("a: .5", 0.5),
        ("a: 00", 0),
        ("a: 012", 12),
        ("a: ~", None),
        ("a: null", None),
        ("a:", None),
        ("a: True", True),
        ("a: FALSE", False),
        ("a: yes", "yes"),
        ("a: off", "off"),
        ("a: 12:30", "12:30"),
        ("a: 'it''s'", "it's"),
        ('a: "tab\\tx"', "tab\tx"),
        ('a: "\\u00e9"', "\u00e9"),
        ("a: b # comment", "b"),
        ("a: http://x#y", "http://x#y"),
        ("a: 'a # not a comment'", "a # not a comment"),
    ],
)
def test_scalar_typing_follows_yaml_1_2(text, expected):
    assert load(text) == {"a": expected}


def test_leading_zero_numbers_are_integers_not_floats():
    # YAML 1.2 core schema: [-+]?[0-9]+ is an integer. Account ids must be quoted to keep their zeros.
    value = load("a: 012345678901")["a"]
    assert value == 12345678901 and isinstance(value, int)


def test_special_floats():
    data = load("a: .inf\nb: -.Inf\nc: .nan\n")
    assert data["a"] == math.inf and data["b"] == -math.inf and math.isnan(data["c"])


def test_literal_block_scalars_and_chomping():
    assert load("k: |\n  line1\n  line2\n") == {"k": "line1\nline2\n"}
    assert load("k: |-\n  strip\n") == {"k": "strip"}
    assert load("k: |+\n  keep\n\nb: 1\n") == {"k": "keep\n\n", "b": 1}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a: |+\n  x\n", "x\n"),
        ("a: |+\n  x\n\n", "x\n\n"),
        ("a: |\n  x", "x"),
        ("a: |+\n  x", "x"),
        ("a: >\n  x\n  y", "x y"),
    ],
)
def test_block_scalar_at_end_of_stream(text, expected):
    assert load(text) == {"a": expected}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a: >\n  folded\n  text\n", "folded text\n"),
        ("a: >\n  folded\n  text\n\n  para\n", "folded text\npara\n"),
        ("a: >\n  one\n  two\n\n\n  three\n", "one two\n\nthree\n"),
        ("a: >\n  one\n    code\n  two\n", "one\n  code\ntwo\n"),
        ("a: >\n  one\n\n    code\n\n  two\n", "one\n\n  code\n\ntwo\n"),
        ("a: >\n\n  lead\n", "\nlead\n"),
        ("a: >-\n  x\n  y\n\n", "x y"),
        ("a: >+\n  x\n\n", "x\n\n"),
    ],
)
def test_folded_block_scalars(text, expected):
    assert load(text) == {"a": expected}


def test_explicit_indentation_indicator():
    assert load("a: |2\n    indented\n") == {"a": "  indented\n"}


def test_plain_and_quoted_multi_line_scalars():
    assert load("a: plain\n  continued\n") == {"a": "plain continued"}
    assert load("a: 'multi\n  line'\n") == {"a": "multi line"}


def test_sequences_and_nesting():
    assert load("- a\n- b: 1\n  c: 2\n- - n1\n  - n2\n") == ["a", {"b": 1, "c": 2}, ["n1", "n2"]]
    assert load("a:\n- 1\n- 2\nb: -1\n") == {"a": [1, 2], "b": -1}


def test_flow_collections():
    assert load("list: [a, 'b c', {k: v}]\nempty: []\nemptym: {}\n") == {
        "list": ["a", "b c", {"k": "v"}],
        "empty": [],
        "emptym": {},
    }
    assert load('a: {x: "1, 2", y: [3]}') == {"a": {"x": "1, 2", "y": [3]}}
    # Spaces inside a flow entry are part of the plain scalar, as in other YAML readers.
    assert load("a: [1 2]") == {"a": ["1 2"]}


def test_keys_with_spaces_and_quoted_keys():
    assert load('key with spaces: v\n"quoted: key": 2\n') == {"key with spaces": "v", "quoted: key": 2}


def test_anchors_aliases_and_merge_keys():
    data = load("base: &b {x: 1, y: [1, 2]}\nchild:\n  <<: *b\n  z: 3\nref: *b\n")
    assert data["child"] == {"x": 1, "y": [1, 2], "z": 3}
    assert data["ref"] == {"x": 1, "y": [1, 2]}


def test_tags_are_ignored():
    assert load("a: !custom value") == {"a": "value"}


def test_multi_document_streams():
    assert load_all("---\na: 1\n---\nb: 2\n") == [{"a": 1}, {"b": 2}]
    assert load("---\na: 1\n---\nb: 2\n") == {"a": 1}


def test_empty_stream():
    assert load("") is None
    assert load("\n# only a comment\n") is None


@pytest.mark.parametrize(
    "text",
    [
        "a: [unclosed\n",
        "a: {x: 1\n",
        'a: "unterminated\n',
        "a: 'unterminated\n",
        "a: *missing\n",
        "a:\n\t- tab\n",
        "a: 1\n   b: 2\n",
        "a: [1] trailing\n",
        "a: |x\n  bad header\n",
        "just a line\nb: 1\n",
    ],
)
def test_errors_raise_yamlerror(text):
    with pytest.raises(YAMLError):
        load(text)


def test_mis_indented_key_is_an_error_not_part_of_the_value():
    # Before 0.3.0 this read as {"protected_roles": "Admin deny_root_user: true"}.
    with pytest.raises(YAMLError, match="line 2: unexpected indentation"):
        load("protected_roles: Admin\n  deny_root_user: true\n")


def test_content_after_a_top_level_scalar_is_an_error_not_dropped():
    # Before 0.3.0 the second line was read as a second document and silently ignored by load().
    with pytest.raises(YAMLError, match="line 2: content after the end of the document"):
        load("just a line\nb: 1\n")
    assert load_all("a\n---\nb: 1\n") == ["a", {"b": 1}]
    assert load_all("a\n...\n---\nb: 1\n") == ["a", {"b": 1}]
