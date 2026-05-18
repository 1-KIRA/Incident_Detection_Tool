import secrets

def generate_session_token():
    # Log the token generation event (kept for existing behavior)
    print('LOG: Creating cryptographically secure session configuration')
    # Generate a secure random 6-digit token
    token = secrets.randbelow(900000) + 100000  # ensures a number between 100000 and 999999 inclusive
    return str(token)