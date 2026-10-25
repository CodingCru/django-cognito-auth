from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import jwt
import requests
import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings

from django_cognito_auth.auth import CognitoAuth, CognitoAuthError
from django_cognito_auth.schemas import CognitoIdentity, CognitoUserData


@pytest.fixture
def rsa_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


@pytest.fixture
def mock_jwks_client(rsa_keys: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]) -> MagicMock:
    _, public_key = rsa_keys
    signing_key = MagicMock()
    signing_key.key = public_key
    client = MagicMock()
    client.get_signing_key_from_jwt.return_value = signing_key
    return client


def make_token(private_key: rsa.RSAPrivateKey, **overrides: object) -> str:
    payload: dict[str, object] = {
        "sub": "test-sub",
        "email": "test@example.com",
        "iss": CognitoAuth._issuer(),
        "aud": settings.COGNITO_CLIENT_ID,
        "token_use": "id",
        "exp": datetime.now(tz=UTC) + timedelta(hours=1),
        "iat": datetime.now(tz=UTC),
    }
    payload.update(overrides)
    return jwt.encode(payload, private_key, algorithm="RS256")


class TestParseIdToken:
    def setup_method(self) -> None:
        CognitoAuth._jwks_client = None

    def test_valid_token_returns_user_data(
        self,
        rsa_keys: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
        mock_jwks_client: MagicMock,
    ) -> None:
        private_key, _ = rsa_keys
        with patch.object(
            CognitoAuth, "get_jwks_client", return_value=mock_jwks_client
        ):
            result = CognitoAuth.parse_id_token(make_token(private_key))
        assert result.sub == "test-sub"
        assert result.email == "test@example.com"

    def test_invalid_token_raises(self) -> None:
        with pytest.raises(jwt.exceptions.DecodeError):
            CognitoAuth.parse_id_token("not.a.jwt")

    def test_expired_token_raises(
        self,
        rsa_keys: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
        mock_jwks_client: MagicMock,
    ) -> None:
        private_key, _ = rsa_keys
        token = make_token(private_key, exp=datetime.now(tz=UTC) - timedelta(hours=1))
        with patch.object(
            CognitoAuth, "get_jwks_client", return_value=mock_jwks_client
        ):
            with pytest.raises(jwt.exceptions.ExpiredSignatureError):
                CognitoAuth.parse_id_token(token)

    def test_wrong_audience_raises(
        self,
        rsa_keys: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
        mock_jwks_client: MagicMock,
    ) -> None:
        private_key, _ = rsa_keys
        token = make_token(private_key, aud="wrong-client-id")
        with patch.object(
            CognitoAuth, "get_jwks_client", return_value=mock_jwks_client
        ):
            with pytest.raises(jwt.exceptions.InvalidAudienceError):
                CognitoAuth.parse_id_token(token)

    def test_wrong_issuer_raises(
        self,
        rsa_keys: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
        mock_jwks_client: MagicMock,
    ) -> None:
        private_key, _ = rsa_keys
        token = make_token(private_key, iss="https://evil.example.com")
        with patch.object(
            CognitoAuth, "get_jwks_client", return_value=mock_jwks_client
        ):
            with pytest.raises(jwt.exceptions.InvalidIssuerError):
                CognitoAuth.parse_id_token(token)

    def test_access_token_use_raises(
        self,
        rsa_keys: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
        mock_jwks_client: MagicMock,
    ) -> None:
        private_key, _ = rsa_keys
        token = make_token(private_key, token_use="access")
        with patch.object(
            CognitoAuth, "get_jwks_client", return_value=mock_jwks_client
        ):
            with pytest.raises(jwt.exceptions.InvalidTokenError, match="Not an ID token"):
                CognitoAuth.parse_id_token(token)


def make_client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, "InitiateAuth")


class TestInitiateUserPasswordAuth:
    def test_success_returns_tokens(self) -> None:
        mock_client = MagicMock()
        mock_client.initiate_auth.return_value = {
            "AuthenticationResult": {
                "AccessToken": "access-123",
                "IdToken": "id-123",
                "TokenType": "Bearer",
                "ExpiresIn": 3600,
                "RefreshToken": "refresh-123",
            }
        }
        with patch("django_cognito_auth.auth.boto3.client", return_value=mock_client):
            tokens = CognitoAuth.initiate_user_password_auth(
                "student@example.com", "password"
            )
        assert tokens.access_token == "access-123"
        assert tokens.id_token == "id-123"
        assert tokens.refresh_token == "refresh-123"

    def test_wrong_password_raises_generic_message(self) -> None:
        mock_client = MagicMock()
        mock_client.initiate_auth.side_effect = make_client_error(
            "NotAuthorizedException"
        )
        with patch("django_cognito_auth.auth.boto3.client", return_value=mock_client):
            with pytest.raises(CognitoAuthError, match="Invalid email or password"):
                CognitoAuth.initiate_user_password_auth("student@example.com", "wrong")

    def test_unknown_user_raises_same_generic_message(self) -> None:
        """Must not reveal whether the email or the password was wrong."""
        mock_client = MagicMock()
        mock_client.initiate_auth.side_effect = make_client_error(
            "UserNotFoundException"
        )
        with patch("django_cognito_auth.auth.boto3.client", return_value=mock_client):
            with pytest.raises(CognitoAuthError, match="Invalid email or password"):
                CognitoAuth.initiate_user_password_auth("nobody@example.com", "pw")

    def test_unconfirmed_user_raises_distinct_message(self) -> None:
        mock_client = MagicMock()
        mock_client.initiate_auth.side_effect = make_client_error(
            "UserNotConfirmedException"
        )
        with patch("django_cognito_auth.auth.boto3.client", return_value=mock_client):
            with pytest.raises(CognitoAuthError, match="confirm your email"):
                CognitoAuth.initiate_user_password_auth("student@example.com", "pw")

    def test_other_client_error_propagates(self) -> None:
        mock_client = MagicMock()
        mock_client.initiate_auth.side_effect = make_client_error(
            "TooManyRequestsException"
        )
        with patch("django_cognito_auth.auth.boto3.client", return_value=mock_client):
            with pytest.raises(ClientError):
                CognitoAuth.initiate_user_password_auth("student@example.com", "pw")

    def test_secret_hash_included_when_client_secret_set(self, settings: Any) -> None:
        settings.COGNITO_CLIENT_SECRET = "shh"
        mock_client = MagicMock()
        mock_client.initiate_auth.return_value = {
            "AuthenticationResult": {
                "AccessToken": "a",
                "IdToken": "i",
                "TokenType": "Bearer",
                "ExpiresIn": 3600,
            }
        }
        with patch("django_cognito_auth.auth.boto3.client", return_value=mock_client):
            CognitoAuth.initiate_user_password_auth("student@example.com", "password")
        call_kwargs = mock_client.initiate_auth.call_args.kwargs
        assert "SECRET_HASH" in call_kwargs["AuthParameters"]

    def test_secret_hash_omitted_when_client_secret_unset(self) -> None:
        mock_client = MagicMock()
        mock_client.initiate_auth.return_value = {
            "AuthenticationResult": {
                "AccessToken": "a",
                "IdToken": "i",
                "TokenType": "Bearer",
                "ExpiresIn": 3600,
            }
        }
        with patch("django_cognito_auth.auth.boto3.client", return_value=mock_client):
            CognitoAuth.initiate_user_password_auth("student@example.com", "password")
        call_kwargs = mock_client.initiate_auth.call_args.kwargs
        assert "SECRET_HASH" not in call_kwargs["AuthParameters"]


def make_error_response(status_code: int, body: bytes) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response.url = "https://pool.auth.eu-west-1.amazoncognito.com/oauth2/token"
    response.encoding = "utf-8"
    response._content = body
    return response


class TestExchangeCodeHttpErrors:
    def setup_method(self) -> None:
        CognitoAuth._session = None

    def test_http_error_raises_cognito_auth_error(self) -> None:
        session = MagicMock()
        session.post.return_value = make_error_response(400, b'{"error": "invalid_grant"}')
        with patch.object(CognitoAuth, "get_session", return_value=session):
            with pytest.raises(CognitoAuthError) as exc_info:
                CognitoAuth.exchange_code("auth-code")
        assert not isinstance(exc_info.value, requests.HTTPError)
        assert isinstance(exc_info.value.__cause__, requests.HTTPError)
        assert "400" in str(exc_info.value)
        assert "invalid_grant" in str(exc_info.value)


class TestGetUserInfo:
    def setup_method(self) -> None:
        CognitoAuth._session = None

    def test_http_error_raises_cognito_auth_error(self) -> None:
        session = MagicMock()
        session.get.return_value = make_error_response(401, b'{"message": "Invalid token"}')
        with patch.object(CognitoAuth, "get_session", return_value=session):
            with pytest.raises(CognitoAuthError) as exc_info:
                CognitoAuth.get_user_info("access-token")
        assert not isinstance(exc_info.value, requests.HTTPError)
        assert isinstance(exc_info.value.__cause__, requests.HTTPError)
        assert "401" in str(exc_info.value)
        assert "Invalid token" in str(exc_info.value)

    def test_non_json_error_body_is_not_leaked(self) -> None:
        session = MagicMock()
        session.get.return_value = make_error_response(
            502, b"<html><body>Bad gateway</body></html>"
        )
        with patch.object(CognitoAuth, "get_session", return_value=session):
            with pytest.raises(CognitoAuthError) as exc_info:
                CognitoAuth.get_user_info("access-token")
        assert "Bad gateway" not in str(exc_info.value)
        assert "502" in str(exc_info.value)


class TestGetProvider:
    def test_no_identities_returns_cognito(self) -> None:
        user_data = CognitoUserData(sub="sub-1", email="a@example.com")
        assert user_data.get_provider() == "cognito"

    def test_empty_identities_returns_cognito(self) -> None:
        user_data = CognitoUserData(sub="sub-1", email="a@example.com", identities=[])
        assert user_data.get_provider() == "cognito"

    def test_google_identity_returns_google(self) -> None:
        user_data = CognitoUserData(
            sub="sub-1", identities=[CognitoIdentity(providerName="Google")]
        )
        assert user_data.get_provider() == "google"

    def test_provider_name_is_case_insensitive(self) -> None:
        user_data = CognitoUserData(
            sub="sub-1", identities=[CognitoIdentity(providerName="GOOGLE")]
        )
        assert user_data.get_provider() == "google"

    def test_unknown_federated_provider_returns_cognito(self) -> None:
        user_data = CognitoUserData(
            sub="sub-1", identities=[CognitoIdentity(providerName="Facebook")]
        )
        assert user_data.get_provider() == "cognito"


class TestExchangeCode:
    def mock_session(self) -> MagicMock:
        session = MagicMock()
        session.post.return_value.json.return_value = {
            "access_token": "access-123",
            "id_token": "id-123",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        return session

    def test_success_without_state_kwargs(self) -> None:
        """Omitting both state kwargs preserves the pre-#5 unchecked behavior."""
        session = self.mock_session()
        with patch.object(CognitoAuth, "get_session", return_value=session):
            tokens = CognitoAuth.exchange_code("auth-code")
        assert tokens.access_token == "access-123"
        session.post.assert_called_once()

    def test_success_with_matching_state(self) -> None:
        session = self.mock_session()
        with patch.object(CognitoAuth, "get_session", return_value=session):
            tokens = CognitoAuth.exchange_code(
                "auth-code", expected_state="abc", received_state="abc"
            )
        assert tokens.access_token == "access-123"
        session.post.assert_called_once()

    def test_mismatched_state_raises_before_network_call(self) -> None:
        session = self.mock_session()
        with patch.object(CognitoAuth, "get_session", return_value=session):
            with pytest.raises(CognitoAuthError, match="Invalid or missing OAuth state"):
                CognitoAuth.exchange_code(
                    "auth-code", expected_state="abc", received_state="xyz"
                )
        session.post.assert_not_called()

    def test_missing_received_state_raises_before_network_call(self) -> None:
        session = self.mock_session()
        with patch.object(CognitoAuth, "get_session", return_value=session):
            with pytest.raises(CognitoAuthError, match="Invalid or missing OAuth state"):
                CognitoAuth.exchange_code("auth-code", expected_state="abc")
        session.post.assert_not_called()


class TestState:
    def test_generate_state_is_random_and_url_safe(self) -> None:
        a = CognitoAuth.generate_state()
        b = CognitoAuth.generate_state()
        assert a != b
        assert len(a) > 20

    def test_matching_state_verifies(self) -> None:
        state = CognitoAuth.generate_state()
        assert CognitoAuth.verify_state(state, state) is True

    def test_mismatched_state_fails(self) -> None:
        assert CognitoAuth.verify_state("abc", "xyz") is False

    def test_missing_expected_fails(self) -> None:
        assert CognitoAuth.verify_state(None, "xyz") is False

    def test_missing_received_fails(self) -> None:
        assert CognitoAuth.verify_state("abc", None) is False

    def test_both_missing_fails(self) -> None:
        assert CognitoAuth.verify_state(None, None) is False
