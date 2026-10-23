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
pip install git+https://github.com/CodingCru/django-cognito-auth.git@v0.2.0
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

# Redirect to the hosted UI — generate a state value, stash it in a
# cookie, and append it to the Cognito URL. See docs/wiring-up-state.md
# for the full double-submit-cookie pattern, including the client-side
# redirect case (a plain `<a href>` instead of a Django view).
state = CognitoAuth.generate_state()
response = redirect(f"{hosted_ui_url}&state={state}")
response.set_cookie("oauth_state", state, httponly=True, samesite="Lax")

# Hosted-UI redirect callback — pass both state values so a mismatch
# raises CognitoAuthError before any request reaches Cognito.
try:
    tokens = CognitoAuth.exchange_code(
        request.GET["code"],
        expected_state=request.COOKIES.get("oauth_state"),
        received_state=request.GET.get("state"),
    )
except CognitoAuthError:
    # Invalid/missing state — reject the callback, don't exchange the code.
    ...
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

- **OAuth `state`**: pass `expected_state`/`received_state` to
  `exchange_code()` as shown above — see
  [`docs/wiring-up-state.md`](docs/wiring-up-state.md) for the full
  double-submit-cookie pattern, including the client-side-redirect case
  (a plain `<a href>` to a prebuilt URL, not a Django view).
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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Found a security issue? See [SECURITY.md](SECURITY.md) instead of opening a public issue.
