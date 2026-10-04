"""Shared helpers and the standard-library YAML reader used for specs."""

import pytest

from scp_guardrails import _miniyaml
from scp_guardrails.policy import (
    PolicyError,
    action_covers,
    as_list,
    find_line,
    parse_policy_text,
    split_operator,
    statement_covers,
    wildcard_match,
)


def test_wildcard_match_is_case_insensitive_and_supports_question_mark():
    assert wildcard_match("ec2:Describe*", "EC2:DescribeInstances")
    assert wildcard_match("s3:Get?bject", "s3:GetObject")
    assert not wildcard_match("ec2:Describe*", "ec2:RunInstances")


def test_policy_variables_act_as_wildcards():
    assert wildcard_match("arn:aws:iam::${aws:PrincipalAccount}:role/Admin", "arn:aws:iam::123456789012:role/Admin")


def test_brackets_are_literal():
    assert not wildcard_match("s3:[G]etObject", "s3:GetObject")


def test_statement_covers_action_and_notaction():
    assert statement_covers({"Action": "sts:*"}, "sts:AssumeRole")
    assert not statement_covers({"NotAction": ["sts:*"]}, "sts:AssumeRole")
    assert statement_covers({"NotAction": ["iam:*"]}, "sts:AssumeRole")
    assert action_covers(["*"], "anything:AtAll")


def test_split_operator():
    assert split_operator("ForAnyValue:StringLikeIfExists") == ("ForAnyValue", "StringLike", True)
    assert split_operator("ArnNotLike") == ("", "ArnNotLike", False)


def test_as_list():
    assert as_list(None) == [] and as_list("a") == ["a"] and as_list(["a"]) == ["a"]


def test_parse_describe_policy_with_object_content():
    doc = parse_policy_text('{"Policy": {"Content": {"Statement": []}}}')
    assert doc == {"Statement": []}


def test_parse_errors():
    with pytest.raises(PolicyError):
        parse_policy_text("{")


def test_find_line():
    text = '{\n "Statement": [\n  {"Sid": "A"},\n  {"Sid": "B"}\n ]\n}'
    assert find_line(text, "B") == 4 and find_line(text, "Z") == 1 and find_line(text, "#0") == 1


def test_miniyaml_reads_spec_shapes():
    data = _miniyaml.load('a: [x, "y"]\nb: true\nc: 3000\nd:\n  - "111122223333"\ne: Owner\n')
    assert data == {"a": ["x", "y"], "b": True, "c": 3000, "d": ["111122223333"], "e": "Owner"}


def test_miniyaml_keeps_yes_as_a_string_and_reports_errors():
    assert _miniyaml.load("x: yes") == {"x": "yes"}
    with pytest.raises(_miniyaml.YAMLError):
        _miniyaml.load("a: [unclosed\n")
