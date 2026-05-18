import secrets

def generate_session_token():
    # Log the token generation event (kept for existing behavior)
    print('LOG: Creating cryptographically secure session configuration')
    # Generate a secure random token with at least 128 bits of entropy
    token = secrets.token_urlsafe(16)
    return token