from abc import ABC, abstractmethod
from pydantic import BaseModel
from typing import Optional, Dict, Any
import httpx
import asyncio 
from urllib.parse import urlencode
import msal
from models import User


class AuthResult(BaseModel):
    token: Dict[str, Any]
    user: User

class AuthProvider(ABC):
    @abstractmethod
    def get_auth_url(self, state: Optional[str] = None) -> str:
        pass

    @abstractmethod
    async def process_callback(self, code: str) -> Optional[AuthResult]:  # Make abstract method async
        pass

class GoogleAuth(AuthProvider):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: Optional[list] = None
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes or ["openid", "email", "profile"]

    def get_auth_url(self, state: Optional[str] = None) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "redirect_uri": self.redirect_uri,
            "state": state,
            "access_type": "offline"
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    
    async def process_callback(self, code: str) -> Optional[AuthResult]:  # Make method async
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        async with httpx.AsyncClient() as client:  # Use async client
            response = await client.post(token_url, data=data)
        if not response.is_success:
            return None
        tokens = response.json()

        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        headers = {"Authorization": f"Bearer {tokens.get('access_token')}"}
        async with httpx.AsyncClient() as client:  # Use async client
            response = await client.get(userinfo_url, headers=headers)
        if not response.is_success:
            return None
        user_info = response.json()

        return AuthResult(
            token=tokens,
            user=User(
                email=user_info.get("email"),
                name=user_info.get("name")
            )
        )

class MicrosoftAuth(AuthProvider):
    def __init__(
        self,
        client_id: str,
        authority: str,
        redirect_uri: str,
        scopes: Optional[list] = None,
        client_secret: Optional[str] = None
    ):
        self.client_id = client_id
        self.authority = authority
        self.redirect_uri = redirect_uri
        self.scopes = scopes or ["User.Read"]
        self.client_secret = client_secret

        self.app = msal.ConfidentialClientApplication(
            client_id=client_id,
            authority=authority,
            client_credential=client_secret
        )

    def get_auth_url(self, state: Optional[str] = None) -> str:
        return self.app.get_authorization_request_url(
            scopes=self.scopes,
            redirect_uri=self.redirect_uri,
            state=state
        )

    async def process_callback(self, code: str) -> Optional[AuthResult]:  # Make method async
        loop = asyncio.get_running_loop()
        try:
            # Run blocking MSAL call in a thread to avoid blocking the event loop
            result = await loop.run_in_executor(
                None,
                lambda: self.app.acquire_token_by_authorization_code(
                    code=code,
                    scopes=self.scopes,
                    redirect_uri=self.redirect_uri
                )
            )
        except Exception as e:
            return None
        if "error" in result:
            return None
        claims = result.get("id_token_claims", {})
        return AuthResult(
            token=result,
            user=User(
                email=claims.get("preferred_username"),
                name=claims.get("name")
            )
        )