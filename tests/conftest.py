import os
import pytest
from pyiboss.client import IBossClient

@pytest.fixture(scope="session")
def iboss_client():
    username = os.environ.get("IBOSS_USERNAME", "crawfordd4@scsk12.org")
    password = os.environ.get("IBOSS_PASSWORD", "Yellow aware speech breathe 1")
    totp = os.environ.get("IBOSS_TOTP")
    
    if not totp:
        pytest.skip("IBOSS_TOTP environment variable not set. Skipping tests that require real authentication.")
        
    client = IBossClient(username, password, totp)
    client.connect()
    return client
