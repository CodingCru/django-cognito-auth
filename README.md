# django-cognito-auth

AWS Cognito authentication core for Django: JWT verification against JWKS,
OAuth2 hosted-UI code exchange, and native `USER_PASSWORD_AUTH` login.

This package is deliberately small — it has no models, no views, no
opinion about your user model. It gives you a `CognitoAuth` class that
turns a Cognito authorization code or a login form into verified user
data; what you do with that (create a user, link an identity, start a
session) is up to your app.

Extracted from [examerio](https://github.com/CodingCru/examerio).

## Install

```bash
pip install git+https://github.com/CodingCru/django-cognito-auth.git@v0.1.0
```

## Settings

```python
COGNITO_CLIENT_ID = "..."
COGNITO_CLIENT_SECRET = ""  # optional — only for confidential app clients
COGNITO_DOMAIN = "https://your-pool.auth.<region>.amazoncognito.com"
COGNITO_REDIRECT_URI = "https://yourapp.com/auth/callback"
COGNITO_USER_POOL_ID = "<region>_<id>"
```

## Usage

```python
from django_cognito_auth import CognitoAuth, CognitoAuthError

# Hosted-UI redirect callback
tokens = CognitoAuth.exchange_code(code)
user_data = CognitoAuth.parse_id_token(tokens.id_token)
if not user_data.email:
    info = CognitoAuth.get_user_info(tokens.access_token)
    user_data.email = info.get("email")

# Native email/password login
try:
    tokens = CognitoAuth.initiate_user_password_auth(email, password)
except CognitoAuthError as exc:
    # exc.args[0] is a user-safe message ("Invalid email or password.", etc)
    ...
```

`user_data.get_provider()` returns `"google"` for a federated Google
login, `"cognito"` otherwise — useful as the `provider` value if you're
linking identities to a local user record.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy src
```
