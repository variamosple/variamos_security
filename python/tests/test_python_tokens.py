from variamos_security import SessionUser, create_jwt, validate_session

USER = SessionUser(
    id="user-1",
    name="Ada",
    user="ada",
    email="ada@example.com",
    roles=["Developer"],
    permissions=["projects::query"],
)


def test_accepts_a_token_it_signed_with_a_host_audience(python_keys):
    response = validate_session(create_jwt(USER, "app.variamos.com"))

    assert response.errorCode is None
    assert response.data.sub == "user-1"
    assert response.data.aud == "app.variamos.com"


def test_accepts_a_token_it_signed_with_a_list_audience(python_keys):
    token = create_jwt(USER, ["variamos-platform", "app.variamos.com"])

    response = validate_session(token)

    assert response.errorCode is None
    assert response.data.aud == ["variamos-platform", "app.variamos.com"]


def test_refuses_an_expired_token(python_keys, monkeypatch):
    monkeypatch.setenv("VARIAMOS_JWT_EXP_IN_SECONDS", "-60")

    response = validate_session(create_jwt(USER))

    assert response.errorCode == 401
    assert "expired" in response.message


def test_refuses_a_token_without_signature_check(python_keys):
    header, payload, _ = create_jwt(USER).split(".")

    response = validate_session(f"{header}.{payload}.forged")

    assert response.errorCode == 401
