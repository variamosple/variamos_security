"""
The claims a session token must carry besides its signature: who issued it
(iss) and what it is for (aud). The same rules as config/TokenClaims.ts of the
Node library: every VariaMos service accepts the same session token (single
sign-on), so the audience names the platform, not one service.
"""

import logging
import os
from typing import Any, List, Mapping, Optional

logger = logging.getLogger(__name__)

DEFAULT_JWT_ISSUER = "variamos_ms_admin"
DEFAULT_JWT_AUDIENCE = "variamos-platform"

# The only algorithm the issuer signs with
JWT_ALGORITHMS = ["RS256"]

# Clock difference accepted between services, in seconds
JWT_CLOCK_TOLERANCE_SECONDS = 30

# What a verifier does with a token whose issuer or audience is wrong or
# missing: "off" nothing; "warn" (default) accepts it and logs it; "enforce"
# refuses it
CLAIMS_MODES = ("off", "warn", "enforce")

_unknown_mode_logged = False


def jwt_issuer() -> str:
    """VARIAMOS_JWT_ISSUER, or the default issuer."""
    return os.getenv("VARIAMOS_JWT_ISSUER", "").strip() or DEFAULT_JWT_ISSUER


def jwt_audience() -> str:
    """VARIAMOS_JWT_AUDIENCE, or the default platform audience."""
    return os.getenv("VARIAMOS_JWT_AUDIENCE", "").strip() or DEFAULT_JWT_AUDIENCE


def claims_mode() -> str:
    """VARIAMOS_JWT_CLAIMS_MODE; an unknown value counts as "warn"."""
    global _unknown_mode_logged
    value = os.getenv("VARIAMOS_JWT_CLAIMS_MODE", "").strip().lower()
    if not value:
        return "warn"
    if value in CLAIMS_MODES:
        return value
    if not _unknown_mode_logged:
        _unknown_mode_logged = True
        logger.warning(
            'VARIAMOS_JWT_CLAIMS_MODE "%s" is not one of %s: "warn" is used',
            value,
            ", ".join(CLAIMS_MODES),
        )
    return "warn"


def _audiences(aud: Any) -> List[Any]:
    if isinstance(aud, list):
        return aud
    return [] if aud is None else [aud]


def claims_problem(payload: Mapping[str, Any]) -> Optional[str]:
    """
    Why the issuer or the audience of a verified payload is not the expected
    one, or None when both are.
    """
    issuer = jwt_issuer()
    iss = payload.get("iss")
    if iss != issuer:
        return "no issuer (iss)" if iss is None else f'issuer (iss) is not "{issuer}"'
    audience = jwt_audience()
    if audience not in _audiences(payload.get("aud")):
        return f'audience (aud) does not hold "{audience}"'
    return None


def audience_host(aud: Any) -> Optional[str]:
    """
    The host a token was issued for, without the platform audience: the aud
    of a session token holds both, [platform, host]. A token issued before
    variamos-security 0.0.17 (Node) holds the host alone.
    """
    platform = jwt_audience()
    return next(
        (entry for entry in _audiences(aud) if isinstance(entry, str) and entry != platform),
        None,
    )
