# Wiring up OAuth `state` (login CSRF protection)

Cognito's hosted-UI flow redirects the browser to Cognito, then back to
your callback URL with a `code`. Without the `state` check, an attacker
can trick a victim's browser into completing *the attacker's* login flow
on the victim's session — the victim ends up authenticated as the
attacker, under their session cookie. `state` defeats this by proving the
callback request belongs to the same browser that started the redirect.

This package gives you the primitives (`generate_state`, `verify_state`,
and `exchange_code()`'s `expected_state`/`received_state` kwargs) but not
the views — wiring up where the value is stored and read is your app's
job. This doc walks through both ways to do that.

## The pattern: double-submit cookie

1. Before redirecting to the hosted UI, generate a random `state` value.
2. Store it in an `httponly` cookie on the response that does the
   redirect.
3. Append the same value as `&state=...` on the Cognito URL.
4. In your callback view, compare the cookie's value against the `state`
   query param Cognito sends back. They must match.

The cookie never leaves the browser except back to your own domain, so
an attacker driving the victim's browser to Cognito can't forge it.

## Case 1: the redirect happens in a Django view

The simplest case — you build the Cognito URL and issue the redirect
yourself, so generating the state and setting the cookie happen in the
same request.

```python
from django.shortcuts import redirect
from django_cognito_auth import CognitoAuth

def login(request):
    state = CognitoAuth.generate_state()
    hosted_ui_url = (
        f"{settings.COGNITO_DOMAIN}/login"
        f"?client_id={settings.COGNITO_CLIENT_ID}"
        f"&response_type=code&scope=email+openid+phone"
        f"&redirect_uri={settings.COGNITO_REDIRECT_URI}"
        f"&state={state}"
    )
    response = redirect(hosted_ui_url)
    response.set_cookie(
        "oauth_state",
        state,
        httponly=True,
        samesite="Lax",
        secure=not settings.DEBUG,
        max_age=300,  # the hosted-UI round trip should be seconds, not minutes
    )
    return response
```

```python
from django_cognito_auth import CognitoAuth, CognitoAuthError

def auth_callback(request):
    try:
        tokens = CognitoAuth.exchange_code(
            request.GET["code"],
            expected_state=request.COOKIES.get("oauth_state"),
            received_state=request.GET.get("state"),
        )
    except CognitoAuthError:
        # Mismatched or missing state — reject before anything else.
        return HttpResponseForbidden("Invalid login state.")
    # ... parse_id_token, create/link the user, start a session, redirect
```

## Case 2: the redirect happens client-side

If your frontend builds the Cognito URL itself — a plain `<a href>` or a
redirect fired from JS, not a Django view — there's no Django request to
set the cookie on *before* the redirect. Generate the state client-side
instead, and still verify it server-side on the callback:

```javascript
// Frontend: generate a state value, store it, append it to the URL.
const state = crypto.randomUUID();
document.cookie = `oauth_state=${state}; Secure; SameSite=Lax; Path=/`;
const hostedUiUrl = `${COGNITO_DOMAIN}/login?client_id=${CLIENT_ID}` +
  `&response_type=code&scope=email+openid+phone` +
  `&redirect_uri=${REDIRECT_URI}&state=${state}`;
window.location.href = hostedUiUrl;
```

The Django callback view is unchanged from Case 1 — it only cares that
the cookie and the `state` query param match, not which side generated
the value. The cookie can't be `httponly` in this case, since JS has to
set it; that's an acceptable trade-off here because the value is
single-use and short-lived, not a credential.

## What `exchange_code()` does with these

If you pass either `expected_state` or `received_state`, the two are
compared with `verify_state()` (constant-time) *before* any request is
made to Cognito's token endpoint. A mismatch — or either value being
missing — raises `CognitoAuthError` immediately. Passing neither
preserves the old, unchecked behavior, so existing callers aren't broken
by upgrading.
