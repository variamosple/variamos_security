import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import rsa

from variamos_security import load_keys

REPOSITORY = Path(__file__).resolve().parents[2]
NODE_SCRIPT = REPOSITORY / "scripts" / "python-test-token.mjs"
NODE_LIBRARY = REPOSITORY / "dist" / "index.mjs"


def _use_keys(monkeypatch, private_path, public_path):
    if private_path:
        monkeypatch.setenv("VARIAMOS_PRIVATE_KEY_PATH", str(private_path))
    else:
        monkeypatch.delenv("VARIAMOS_PRIVATE_KEY_PATH", raising=False)
    if public_path:
        monkeypatch.setenv("VARIAMOS_PUBLIC_KEY_PATH", str(public_path))
    else:
        monkeypatch.delenv("VARIAMOS_PUBLIC_KEY_PATH", raising=False)
    load_keys()


@pytest.fixture(scope="session")
def python_key_pair(tmp_path_factory):
    """A key pair of the tests alone, written as the services read theirs."""
    directory = tmp_path_factory.mktemp("python-keys")
    public_key, private_key = rsa.newkeys(2048)
    (directory / "private.pem").write_bytes(private_key.save_pkcs1())
    (directory / "public.pem").write_bytes(public_key.save_pkcs1())
    return directory


@pytest.fixture
def python_keys(monkeypatch, python_key_pair):
    """Signs and verifies with the Python package, as before 0.0.17."""
    _use_keys(
        monkeypatch,
        python_key_pair / "private.pem",
        python_key_pair / "public.pem",
    )


@pytest.fixture
def python_private_key_only(monkeypatch, python_key_pair):
    """Only the private key is configured: the issuer's own setting."""
    _use_keys(monkeypatch, python_key_pair / "private.pem", None)


@pytest.fixture(scope="session")
def node_signed(tmp_path_factory):
    """
    Session tokens signed by the built Node library ("session", and with
    another issuer or audience: "otherIssuer", "otherAudience"), with the
    public key that verifies them. Skipped without Node or without the build, unless
    VARIAMOS_REQUIRE_NODE_TOKEN=1 (the CI), where it must work.
    """
    required = os.getenv("VARIAMOS_REQUIRE_NODE_TOKEN") == "1"
    node = shutil.which("node")
    if not node or not NODE_LIBRARY.exists():
        if required:
            pytest.fail("Node and the built library (npm run build) are required")
        pytest.skip("Node or the built library (npm run build) is missing")
    signed = json.loads(
        subprocess.run(
            [node, str(NODE_SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
            cwd=REPOSITORY,
        ).stdout
    )
    public_path = tmp_path_factory.mktemp("node-keys") / "public.pem"
    public_path.write_text(signed["publicKey"])
    return signed["tokens"], public_path


@pytest.fixture
def node_tokens(monkeypatch, node_signed):
    """Verifies with the public key of the Node issuer only, as a service does."""
    tokens, public_path = node_signed
    _use_keys(monkeypatch, None, public_path)
    return tokens


@pytest.fixture
def node_keys(node_tokens):
    """The session token of the Node issuer."""
    return node_tokens["session"]


@pytest.fixture(autouse=True)
def claims_settings(monkeypatch):
    """Each test starts from the default issuer, audience and mode."""
    for name in ("VARIAMOS_JWT_ISSUER", "VARIAMOS_JWT_AUDIENCE", "VARIAMOS_JWT_CLAIMS_MODE"):
        monkeypatch.delenv(name, raising=False)
