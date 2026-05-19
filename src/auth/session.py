import secrets

def generate_session_token():
    # Log the token generation event (kept for existing behavior)
    print('LOG: Creating cryptographically secure session configuration')
    # Generate a cryptographically secure random token with at least 32 alphanumeric characters
    # Using token_urlsafe(24) yields 32 characters (since base64 encoding) with 192 bits of entropy
    token = secrets.token_urlsafe(24)
    return token