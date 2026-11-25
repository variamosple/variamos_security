"""
How long a session token lasts: VARIAMOS_JWT_EXP_IN_SECONDS, a whole number
of seconds above zero. The same rules as config/TokenLifetime.ts of the Node
library: any other value (empty, not a number, negative, zero, a decimal)
would sign a token that cannot be created or is expired at once, so the
default is used instead, and a warning says so.
"""

import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_JWT_EXP_IN_SECONDS = 900

# ASCII digits only: int() would also take "1_000", "+900" or other scripts
_WHOLE_SECONDS = re.compile(r"[0-9]+")

_last_refused_value: Optional[str] = None


def jwt_expires_in_seconds() -> int:
    """VARIAMOS_JWT_EXP_IN_SECONDS, or the default lifetime."""
    global _last_refused_value
    raw = os.getenv("VARIAMOS_JWT_EXP_IN_SECONDS")
    if raw is None:
        return DEFAULT_JWT_EXP_IN_SECONDS
    value = raw.strip()
    seconds = int(value) if _WHOLE_SECONDS.fullmatch(value) else 0
    # The Node library takes no more than its largest safe integer
    if 0 < seconds <= 2**53 - 1:
        return seconds
    # Once per refused value, not at every signature
    if _last_refused_value != raw:
        _last_refused_value = raw
        logger.warning(
            'VARIAMOS_JWT_EXP_IN_SECONDS "%s" is not a whole number of seconds above 0: %d is used',
            raw,
            DEFAULT_JWT_EXP_IN_SECONDS,
        )
    return DEFAULT_JWT_EXP_IN_SECONDS
