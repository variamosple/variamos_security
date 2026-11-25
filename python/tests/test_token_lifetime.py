import logging

import pytest

from variamos_security import SessionUser, create_jwt, validate_session
from variamos_security.config import token_lifetime
from variamos_security.config.token_lifetime import (
    DEFAULT_JWT_EXP_IN_SECONDS,
    jwt_expires_in_seconds,
)
from jose import jwt

USER = SessionUser(
    id="user-1",
    name="Ada",
    user="ada",
    email="ada@example.com",
    roles=["Developer"],
    permissions=["projects::query"],
)

REFUSED = 'is not a whole number of seconds above 0: 900 is used'


@pytest.fixture(autouse=True)
def _no_refused_value_yet(monkeypatch):
    monkeypatch.setattr(token_lifetime, "_last_refused_value", None)


def test_is_900_seconds_without_the_variable_silently(monkeypatch, caplog):
    monkeypatch.delenv("VARIAMOS_JWT_EXP_IN_SECONDS", raising=False)

    with caplog.at_level(logging.WARNING):
        assert jwt_expires_in_seconds() == DEFAULT_JWT_EXP_IN_SECONDS == 900

    assert caplog.text == ""


@pytest.mark.parametrize("value, seconds", [("3600", 3600), (" 60 ", 60), ("1", 1)])
def test_reads_a_whole_number_of_seconds_silently(monkeypatch, caplog, value, seconds):
    monkeypatch.setenv("VARIAMOS_JWT_EXP_IN_SECONDS", value)

    with caplog.at_level(logging.WARNING):
        assert jwt_expires_in_seconds() == seconds

    assert caplog.text == ""


@pytest.mark.parametrize(
    "value",
    ["", "   ", "abc", "15m", "-60", "0", "1.5", "1e3", "+900", "1_000", "٣", "99999999999999999999"],
)
def test_uses_the_default_and_says_it(monkeypatch, caplog, value):
    monkeypatch.setenv("VARIAMOS_JWT_EXP_IN_SECONDS", value)

    with caplog.at_level(logging.WARNING):
        assert jwt_expires_in_seconds() == DEFAULT_JWT_EXP_IN_SECONDS

    assert caplog.text.count(f'VARIAMOS_JWT_EXP_IN_SECONDS "{value}" {REFUSED}') == 1


def test_says_it_once_per_refused_value_not_at_every_signature(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        monkeypatch.setenv("VARIAMOS_JWT_EXP_IN_SECONDS", "-1")
        jwt_expires_in_seconds()
        jwt_expires_in_seconds()
        assert caplog.text.count(REFUSED) == 1

        monkeypatch.setenv("VARIAMOS_JWT_EXP_IN_SECONDS", "-2")
        jwt_expires_in_seconds()
        assert caplog.text.count(REFUSED) == 2


def test_follows_the_variable_when_signing(python_keys, monkeypatch):
    monkeypatch.setenv("VARIAMOS_JWT_EXP_IN_SECONDS", "3600")

    claims = jwt.get_unverified_claims(create_jwt(USER))

    assert claims["exp"] - claims["iat"] == 3600


# An empty lifetime used to stop create_jwt with a ValueError
def test_signs_a_token_of_900_seconds_when_the_variable_is_empty(python_keys, monkeypatch, caplog):
    monkeypatch.setenv("VARIAMOS_JWT_EXP_IN_SECONDS", "")

    with caplog.at_level(logging.WARNING):
        token = create_jwt(USER)

    claims = jwt.get_unverified_claims(token)
    assert claims["exp"] - claims["iat"] == 900
    assert REFUSED in caplog.text
    assert validate_session(token).errorCode is None
