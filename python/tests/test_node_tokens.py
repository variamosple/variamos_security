"""
The Python verifier against a session token signed by the Node library of
this repository, as variamos_ms_admin signs them: what the 0.0.2 verifier
lacked (2026-11-10).
"""

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from variamos_security import (
    SessionUser,
    VariamosSecurityException,
    has_permissions,
    validate_session,
    variamos_security_exception_handler,
)


def test_reads_the_claims_of_a_node_token(node_keys):
    response = validate_session(node_keys)

    assert response.errorCode is None
    assert response.data.sub == "user-1"
    assert response.data.iss == "variamos_ms_admin"
    assert response.data.aud == ["variamos-platform", "app.variamos.com"]
    assert response.data.permissions == ["projects::query"]


def _app(permission):
    app = FastAPI()
    app.add_exception_handler(
        VariamosSecurityException, variamos_security_exception_handler
    )

    @app.get("/projects")
    def projects(user: SessionUser = Depends(has_permissions([permission]))):
        return {"user": user.user}

    return TestClient(app)


def test_lets_a_node_token_through_a_permission_check(node_keys):
    client = _app("projects::query")

    response = client.get(
        "/projects", headers={"Authorization": f"Bearer {node_keys}"}
    )

    assert response.status_code == 200
    assert response.json() == {"user": "node-signed"}


def test_reads_a_node_token_from_the_session_cookie(node_keys):
    client = _app("projects::query")
    client.cookies.set("authToken", node_keys)

    assert client.get("/projects").status_code == 200


def test_refuses_a_node_token_without_the_permission(node_keys):
    client = _app("projects::delete")

    response = client.get(
        "/projects", headers={"Authorization": f"Bearer {node_keys}"}
    )

    assert response.status_code == 403
