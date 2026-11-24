from variamos_security import SessionUser, create_jwt, validate_session

USER = SessionUser(
    id="user-1",
    name="Ada",
    user="ada",
    email="ada@example.com",
    roles=["Developer"],
    permissions=["projects::query"],
)


def test_signs_the_issuer_and_the_platform_audience_with_the_host(python_keys):
    response = validate_session(create_jwt(USER, "app.variamos.com"))

    assert response.errorCode is None
    assert response.data.sub == "user-1"
    assert response.data.iss == "variamos_ms_admin"
    assert response.data.aud == ["variamos-platform", "app.variamos.com"]


def test_signs_the_platform_audience_alone_without_host(python_keys):
    assert validate_session(create_jwt(USER)).data.aud == "variamos-platform"


def test_keeps_the_host_of_a_token_being_refreshed(python_keys):
    token = create_jwt(USER, ["variamos-platform", "app.variamos.com"])

    assert validate_session(token).data.aud == ["variamos-platform", "app.variamos.com"]


def test_passes_the_claims_check_it_signs_for(python_keys, monkeypatch, caplog):
    monkeypatch.setenv("VARIAMOS_JWT_CLAIMS_MODE", "enforce")

    assert validate_session(create_jwt(USER, "app.variamos.com")).errorCode is None
    assert "JWT" not in caplog.text


def test_refuses_an_expired_token(python_keys, monkeypatch):
    monkeypatch.setenv("VARIAMOS_JWT_EXP_IN_SECONDS", "-60")

    response = validate_session(create_jwt(USER))

    assert response.errorCode == 401
    assert "expired" in response.message


def test_refuses_a_token_without_signature_check(python_keys):
    header, payload, _ = create_jwt(USER).split(".")

    response = validate_session(f"{header}.{payload}.forged")

    assert response.errorCode == 401
