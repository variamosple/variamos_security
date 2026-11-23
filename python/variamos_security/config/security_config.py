import os
import logging
from jose import jwk

# Get the logger for this module
logger = logging.getLogger(__name__)

# Define private variables
_private_key = None
_public_key = None

def load_keys():
    logger.info("Loading security keys")
    global _private_key, _public_key

    private_key_pem = None
    public_key_pem = None
    
    private_key_path = os.getenv('VARIAMOS_PRIVATE_KEY_PATH')
    public_key_path = os.getenv('VARIAMOS_PUBLIC_KEY_PATH')

    if private_key_path and os.path.exists(private_key_path):
        with open(private_key_path, 'r') as f:
            private_key_pem = f.read()
        logger.info("Private key loaded successfully")

    if public_key_path and os.path.exists(public_key_path):
        with open(public_key_path, 'r') as f:
            public_key_pem = f.read()
        logger.info("Public key loaded successfully")

    _private_key = jwk.construct(private_key_pem, algorithm='RS256') if private_key_pem else None
    _public_key = jwk.construct(public_key_pem, algorithm='RS256') if public_key_pem else None

    if _private_key:
        logger.info("Private key constructed successfully")
    if _public_key:
        logger.info("Public key constructed successfully")

def get_private_key():
    return _private_key

def get_public_key():
    return _public_key