import logging

import pytest

from variamos_security.config import token_claims
from variamos_security.config.token_claims import (
    audience_host,
    claims_mode,
    claims_problem,
)


@pytest.mark.parametrize(
    "payload, problem",
    [
        ({"iss": "variamos_ms_admin", "aud": ["variamos-platform", "app.variamos.com"]}, None),
        ({"iss": "variamos_ms_admin", "aud": "variamos-platform"}, None),
        ({"aud": "variamos-platform"}, "no issuer (iss)"),
        ({"iss": "other", "aud": "variamos-platform"}, 'issuer (iss) is not "variamos_ms_admin"'),
        # A token issued before 0.0.17 (Node): the host alone
        ({"iss": "variamos_ms_admin", "aud": "app.variamos.com"}, 'audience (aud) does not hold "variamos-platform"'),
        ({"iss": "variamos_ms_admin"}, 'audience (aud) does not hold "variamos-platform"'),
    ],
)
def test_names_what_is_wrong_with_the_claims(payload, problem):
    assert claims_problem(payload) == problem


def test_reads_the_expected_issuer_and_audience_from_the_environment(monkeypatch):
    monkeypatch.setenv("VARIAMOS_JWT_ISSUER", " issuer ")
    monkeypatch.setenv("VARIAMOS_JWT_AUDIENCE", "platform")

    assert claims_problem({"iss": "issuer", "aud": ["platform"]}) is None


@pytest.mark.parametrize("value, mode", [(None, "warn"), ("", "warn"), ("OFF", "off"), (" enforce ", "enforce")])
def test_reads_the_mode(monkeypatch, value, mode):
    if value is not None:
        monkeypatch.setenv("VARIAMOS_JWT_CLAIMS_MODE", value)

    assert claims_mode() == mode


def test_counts_an_unknown_mode_as_warn_and_says_it_once(monkeypatch, caplog):
    monkeypatch.setattr(token_claims, "_unknown_mode_logged", False)
    monkeypatch.setenv("VARIAMOS_JWT_CLAIMS_MODE", "strict")

    with caplog.at_level(logging.WARNING):
        assert claims_mode() == "warn"
        assert claims_mode() == "warn"

    assert caplog.text.count('"strict" is not one of off, warn, enforce') == 1


@pytest.mark.parametrize(
    "aud, host",
    [
        (["variamos-platform", "app.variamos.com"], "app.variamos.com"),
        ("app.variamos.com", "app.variamos.com"),
        ("variamos-platform", None),
        (None, None),
    ],
)
def test_finds_the_host_of_an_audience(aud, host):
    assert audience_host(aud) == host
