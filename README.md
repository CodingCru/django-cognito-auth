# django-cognito-auth

AWS Cognito authentication core for Django: JWT verification against JWKS,
OAuth2 hosted-UI code exchange, and native `USER_PASSWORD_AUTH` login.

This package is deliberately small — it has no models, no views, no
opinion about your user model. It gives you a `CognitoAuth` class that
turns a Cognito authorization code or a login form into verified user
data; what you do with that (create a user, link an identity, start a
session) is up to your app.

## Install

```bash
pip install git+https://github.com/CodingCru/django-cognito-auth.git@v0.1.3
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

## Security notes

- **OAuth `state`**: `CognitoAuth.generate_state()`/`verify_state()` give
  you a random value and a constant-time comparison — but storing and
  attaching it is still on you, since this package has no views. If
  your redirect to Cognito's hosted UI happens client-side (e.g. a
  plain `<a href>` to a prebuilt URL, not a Django view), generate the
  state there instead and verify only on the Django side via a
  double-submit cookie: set the value as a cookie before redirecting,
  append it as `&state=...` on the Cognito URL, then in your callback
  compare the cookie against the `state` Cognito sends back.
- **`UserNotConfirmedException`** confirms an account exists (distinct
  from the generic "invalid email or password" message). Enable
  Cognito's "Prevent user existence errors" pool setting if that's not
  acceptable for your app.
- **`parse_id_token`** is meant for tokens your own server just
  received from Cognito. If you ever use it to verify client-supplied
  bearer tokens instead, an unknown `kid` triggers a JWKS re-fetch per
  request — rate-limit or cache around that.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy src
```
