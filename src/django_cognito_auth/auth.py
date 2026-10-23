import base64
import hashlib
import hmac
import secrets
from typing import Any

import boto3
import jwt
import requests
from botocore.exceptions import ClientError
from django.conf import settings
from jwt import PyJWKClient
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .schemas import CognitoTokens, CognitoUserData


class CognitoAuthError(Exception):
    """Raised for user-facing auth failures (bad credentials, unconfirmed
    account, ...) — the message is safe to show to the end user as-is.
    """


class CognitoAuth:
    _session: requests.Session | None = None
    _jwks_client: PyJWKClient | None = None

    @classmethod
    def base_url(cls) -> str:
        return f"{settings.COGNITO_DOMAIN}/oauth2"

    @classmethod
    def _region(cls) -> str:
        # Pool ID format is "{region}_{id}", e.g. "eu-west-1_Ab3Cd4Ef5"
        return settings.COGNITO_USER_POOL_ID.rsplit("_", 1)[0]

    @classmethod
    def _issuer(cls) -> str:
        return f"https://cognito-idp.{cls._region()}.amazonaws.com/{settings.COGNITO_USER_POOL_ID}"

    @classmethod
    def get_session(cls) -> requests.Session:
        if cls._session is None:
            session = requests.Session()
            retry = Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[500, 502, 503, 504],
            )
            session.mount("https://", HTTPAdapter(max_retries=retry))
            cls._session = session
        return cls._session

    @classmethod
    def get_jwks_client(cls) -> PyJWKClient:
        if cls._jwks_client is None:
            cls._jwks_client = PyJWKClient(f"{cls._issuer()}/.well-known/jwks.json")
        return cls._jwks_client

    @classmethod
    def exchange_code(
        cls,
        code: str,
        *,
        expected_state: str | None = None,
        received_state: str | None = None,
    ) -> CognitoTokens:
        """Exchange a hosted-UI authorization code for tokens.

        Pass `expected_state` (what you stored before redirecting, e.g. a
        cookie) and `received_state` (what the callback request got back)
        to verify the OAuth `state` CSRF check before any network call is
        made. Omit both to preserve the old, unchecked behavior.
        """
        if expected_state is not None or received_state is not None:
            if not cls.verify_state(expected_state, received_state):
                raise CognitoAuthError("Invalid or missing OAuth state.")
        data = {
            "grant_type": "authorization_code",
            "client_id": settings.COGNITO_CLIENT_ID,
            "code": code,
            "redirect_uri": settings.COGNITO_REDIRECT_URI,
        }
        if settings.COGNITO_CLIENT_SECRET:
            data["client_secret"] = settings.COGNITO_CLIENT_SECRET
        response = cls.get_session().post(
            f"{cls.base_url()}/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            timeout=10,
        )
        response.raise_for_status()
        return CognitoTokens.model_validate(response.json())

    @classmethod
    def _secret_hash(cls, username: str) -> str:
        message = username + settings.COGNITO_CLIENT_ID
        digest = hmac.new(
            settings.COGNITO_CLIENT_SECRET.encode(),
            message.encode(),
            hashlib.sha256,
        ).digest()
        return base64.b64encode(digest).decode()

    @classmethod
    def initiate_user_password_auth(cls, email: str, password: str) -> CognitoTokens:
        """Native email/password login — your own login form, as opposed
        to the hosted-UI redirect `exchange_code` serves.
        """
        auth_parameters = {"USERNAME": email, "PASSWORD": password}
        if settings.COGNITO_CLIENT_SECRET:
            auth_parameters["SECRET_HASH"] = cls._secret_hash(email)

        client = boto3.client("cognito-idp", region_name=cls._region())
        try:
            response = client.initiate_auth(
                AuthFlow="USER_PASSWORD_AUTH",
                ClientId=settings.COGNITO_CLIENT_ID,
                AuthParameters=auth_parameters,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "UserNotConfirmedException":
                # Confirms the account exists, unlike the message below —
                # enable Cognito's "Prevent user existence errors" setting
                # if that's unacceptable.
                raise CognitoAuthError(
                    "Please confirm your email before logging in."
                ) from exc
            if code in ("NotAuthorizedException", "UserNotFoundException"):
                # Never reveal which of the two it was.
                raise CognitoAuthError("Invalid email or password.") from exc
            raise

        result = response["AuthenticationResult"]
        return CognitoTokens(
            access_token=result["AccessToken"],
            id_token=result["IdToken"],
            token_type=result["TokenType"],
            expires_in=result["ExpiresIn"],
            refresh_token=result.get("RefreshToken"),
        )

    @classmethod
    def parse_id_token(cls, id_token: str) -> CognitoUserData:
        signing_key = cls.get_jwks_client().get_signing_key_from_jwt(id_token)
        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.COGNITO_CLIENT_ID,
            issuer=cls._issuer(),
        )
        # AWS-recommended check; aud above already rejects access tokens in practice.
        if payload.get("token_use") != "id":
            raise jwt.exceptions.InvalidTokenError("Not an ID token")
        return CognitoUserData.model_validate(payload)

    @classmethod
    def get_user_info(cls, access_token: str) -> dict[str, Any]:
        response = cls.get_session().get(
            f"{cls.base_url()}/userInfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        response.raise_for_status()
        return response.json()

    @classmethod
    def generate_state(cls) -> str:
        """A random value for the OAuth `state` CSRF check — store it
        (e.g. a cookie) before redirecting to Cognito's hosted UI, then
        verify it against what the callback returns.
        """
        return secrets.token_urlsafe(32)

    @classmethod
    def verify_state(cls, expected: str | None, received: str | None) -> bool:
        """Constant-time comparison for the OAuth `state` CSRF check."""
        if not expected or not received:
            return False
        return secrets.compare_digest(expected, received)
