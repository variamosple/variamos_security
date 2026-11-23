from variamos_security import SessionInfo

USER = {
    "sub": "user-1",
    "name": "Ada",
    "userName": "ada",
    "email": "ada@example.com",
}


def test_reads_an_audience_given_as_a_string():
    # Tokens issued before variamos-security 0.0.17 (Node) hold the host alone
    assert SessionInfo(**USER, aud="app.variamos.com").aud == "app.variamos.com"


def test_reads_an_audience_given_as_a_list():
    # Since 0.0.17 (Node), aud is [platform, host]: 0.0.2 refused it with a
    # validation error, and every authenticated request answered 500
    info = SessionInfo(**USER, aud=["variamos-platform", "app.variamos.com"])

    assert info.aud == ["variamos-platform", "app.variamos.com"]


def test_keeps_the_issuer_when_there_is_one():
    assert SessionInfo(**USER, iss="variamos_ms_admin").iss == "variamos_ms_admin"


def test_reads_a_token_without_issuer_nor_audience():
    info = SessionInfo(**USER)

    assert info.iss is None
    assert info.aud is None
