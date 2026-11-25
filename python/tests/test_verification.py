"""
What the verifier refuses, and with which status: claims checked as
VARIAMOS_JWT_CLAIMS_MODE says, a genuine token that is not a session, the key
it verifies with, and the token it reads when a request carries two.
"""

import logging

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from jose import jwt

from variamos_security import (
    SessionUser,
    VariamosSecurityException,
    create_jwt,
    get_private_key,
    has_permissions,
    is_authenticated,
    validate_session,
    variamos_security_exception_handler,
)

PERMITTED = SessionUser(
    id="user-1", name="Ada", user="ada", email="ada@example.com",
    roles=["Developer"], permissions=["projects::query"],
)
NOT_PERMITTED = SessionUser(
    id="user-2", name="Bob", user="bob", email="bob@example.com",
    roles=["Developer"], permissions=["my-account::query"],
)


def _client():
    app = FastAPI()
    app.add_exception_handler(VariamosSecurityException, variamos_security_exception_handler)

    @app.get("/projects")
    def projects(user: SessionUser = Depends(has_permissions(["projects::query"]))):
        return {"user": user.user}

    @app.get("/me")
    def me(user: SessionUser = Depends(is_authenticated)):
        return {"user": user.user}

    return TestClient(app)


# --- issuer and audience -----------------------------------------------------


@pytest.mark.parametrize("kind", ["otherIssuer", "otherAudience"])
def test_accepts_and_logs_other_claims_by_default(node_tokens, kind, caplog):
    with caplog.at_level(logging.WARNING):
        response = validate_session(node_tokens[kind])

    assert response.errorCode is None
    assert "JWT accepted although" in caplog.text


@pytest.mark.parametrize("kind", ["otherIssuer", "otherAudience"])
def test_refuses_other_claims_when_enforced(node_tokens, kind, monkeypatch, caplog):
    monkeypatch.setenv("VARIAMOS_JWT_CLAIMS_MODE", "enforce")

    response = validate_session(node_tokens[kind])

    assert response.errorCode == 401
    assert "JWT refused" in caplog.text


def test_accepts_the_node_session_token_when_enforced(node_tokens, monkeypatch):
    monkeypatch.setenv("VARIAMOS_JWT_CLAIMS_MODE", "enforce")

    assert validate_session(node_tokens["session"]).errorCode is None


def test_says_nothing_about_the_claims_when_off(node_tokens, monkeypatch, caplog):
    monkeypatch.setenv("VARIAMOS_JWT_CLAIMS_MODE", "off")

    with caplog.at_level(logging.WARNING):
        assert validate_session(node_tokens["otherIssuer"]).errorCode is None

    assert "JWT" not in caplog.text


def test_answers_401_to_another_audience_through_fastapi_when_enforced(node_tokens, monkeypatch):
    monkeypatch.setenv("VARIAMOS_JWT_CLAIMS_MODE", "enforce")

    response = _client().get("/projects", headers={"Authorization": f"Bearer {node_tokens['otherAudience']}"})

    assert response.status_code == 401


# --- a genuine token that is not a session -----------------------------------


def _signed(payload):
    return jwt.encode(payload, get_private_key().to_pem().decode("utf-8"), algorithm="RS256")


def test_answers_401_not_500_to_a_token_without_the_session_fields(python_keys, caplog):
    # 0.0.2 answered 500: the validation error of SessionInfo escaped
    token = _signed({"sub": "user-1", "email": "secret@example.com", "exp": 9999999999})

    response = _client().get("/projects", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert "not a session token: name (missing), userName (missing)" in caplog.text
    # The values of the token are not logged
    assert "secret@example.com" not in caplog.text


def test_answers_401_to_a_field_of_the_wrong_type(python_keys):
    token = _signed({"sub": "user-1", "name": "Ada", "userName": "ada", "email": "a@b.c", "roles": "Developer", "exp": 9999999999})

    assert validate_session(token).errorCode == 401


# --- key ---------------------------------------------------------------------


def test_verifies_with_the_public_half_of_a_private_key_alone(python_private_key_only, caplog):
    token = create_jwt(PERMITTED)

    with caplog.at_level(logging.WARNING):
        response = validate_session(token)

    assert response.errorCode is None
    assert "the public half of the private key verifies the session" in caplog.text


# --- two tokens in one request -----------------------------------------------


def test_reads_the_header_when_the_cookie_is_stale(python_keys, sign_expired):
    valid = create_jwt(PERMITTED)
    expired = sign_expired(PERMITTED)
    client = _client()
    client.cookies.set("authToken", expired)

    for path in ("/projects", "/me"):
        response = client.get(path, headers={"Authorization": f"Bearer {valid}"})
        assert response.status_code == 200, path


def test_reads_the_header_when_the_cookie_is_not_a_token(python_keys):
    client = _client()
    client.cookies.set("authToken", "not-a-token")

    response = client.get("/projects", headers={"Authorization": f"Bearer {create_jwt(PERMITTED)}"})

    assert response.status_code == 200


def test_keeps_the_cookie_answer_without_header(python_keys):
    client = _client()
    client.cookies.set("authToken", "not-a-token")

    assert client.get("/projects").status_code == 401


def test_does_not_try_the_header_to_gain_a_permission(python_keys):
    # A valid cookie without the permission is a 403: another token is not
    # tried to gain rights
    client = _client()
    client.cookies.set("authToken", create_jwt(NOT_PERMITTED))

    response = client.get("/projects", headers={"Authorization": f"Bearer {create_jwt(PERMITTED)}"})

    assert response.status_code == 403
