from pydantic import BaseModel


class CognitoIdentity(BaseModel):
    providerName: str
    model_config = {"extra": "ignore"}


class CognitoUserData(BaseModel):
    sub: str
    email: str | None = None
    identities: list[CognitoIdentity] | None = None

    model_config = {"extra": "ignore"}

    def get_provider(self) -> str:
        if self.identities:
            name = self.identities[0].providerName.lower()
            if name in ("google",):
                return name
        return "cognito"


class CognitoTokens(BaseModel):
    access_token: str
    id_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None

    model_config = {"extra": "ignore"}
