## Project Structure
```
    auth_provider.py
    main.py
    models.py
    templates/
    user_provisioner.py
```

## C:\\dev\\fastapi\_google\_starter\\auth\_provider.py
```python
## C:\\dev\\fastapi_google_starter\\auth_provider.py
from abc import ABC, abstractmethod
from pydantic import BaseModel
from typing import Optional, Dict, Any
import requests
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
    def process_callback(self, code: str) -> Optional[AuthResult]:
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
    
    def process_callback(self, code: str) -> Optional[AuthResult]:
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        response = requests.post(token_url, data=data)
        if not response.ok:
            return None
        tokens = response.json()

        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        headers = {"Authorization": f"Bearer {tokens.get('access_token')}"}
        response = requests.get(userinfo_url, headers=headers)
        if not response.ok:
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

    def process_callback(self, code: str) -> Optional[AuthResult]:
        result = self.app.acquire_token_by_authorization_code(
            code=code,
            scopes=self.scopes,
            redirect_uri=self.redirect_uri
        )
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

```

## C:\\dev\\fastapi\_google\_starter\\main.py
```python
## C:\\dev\\fastapi_google_starter\\main.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from auth_provider import AuthProvider, MicrosoftAuth, GoogleAuth
import os
from typing import Optional
from decouple import config
from sqlmodel import SQLModel, create_engine
from models import User
from user_provisioner import UserProvisioner
from fastapi.templating import Jinja2Templates

app = FastAPI()

templates = Jinja2Templates(directory="templates")
# Database setup
DATABASE_URL = "sqlite:///./database.db"
engine = create_engine(DATABASE_URL)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

def get_auth_provider(provider_name: str) -> AuthProvider:
    if provider_name == "google":
        return GoogleAuth(
            client_id=config("GOOGLE_CLIENT_ID"),
            client_secret=config("GOOGLE_CLIENT_SECRET"),
            redirect_uri=config("GOOGLE_REDIRECT_URI")
        )
    elif provider_name == "microsoft":
        return MicrosoftAuth(
            client_id=config("MICROSOFT_CLIENT_ID"),
            authority=f"https://login.microsoftonline.com/{config('MICROSOFT_AUTHORITY')}",
            redirect_uri=config("MICROSOFT_REDIRECT_URI"),
            client_secret=config("MICROSOFT_CLIENT_SECRET", default=None)
        )
    raise ValueError(f"Unknown provider: {provider_name}")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user_name = request.cookies.get("user_name")
    user_email = request.cookies.get("user_email")
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user_name": user_name,
        "user_email": user_email
    })

@app.get("/login/{provider}")
async def login(provider: str):
    try:
        auth_provider = get_auth_provider(provider)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    state = os.urandom(16).hex()
    auth_url = auth_provider.get_auth_url(state=state)
    
    response = RedirectResponse(auth_url)
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        secure=config("ENVIRONMENT", default="development") == "production",
        samesite="Lax",
        max_age=300  # 5 minutes expiration
    )
    return response

@app.get("/auth/{provider}")
async def auth_callback(
    provider: str,
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
):
    stored_state = request.cookies.get("oauth_state")
    if not stored_state or stored_state != state:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    try:
        auth_provider = get_auth_provider(provider)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing")
    
    auth_result = auth_provider.process_callback(code)
    if not auth_result:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    user_email = auth_result.user.email
    user_name = auth_result.user.name or ""
    
    if not user_email:
        raise HTTPException(status_code=400, detail="Email not provided by the provider.")
    
    # Provision user
    provisioner = UserProvisioner(engine)
    provisioner.provision_user(email=user_email, name=user_name)
    
    response = RedirectResponse(url="/")
    response.set_cookie("user_email", user_email or "", path="/")
    response.set_cookie("user_name", user_name or "", path="/")
    response.delete_cookie("oauth_state")
    
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie("user_name", path="/")
    response.delete_cookie("user_email", path="/")
    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

## C:\\dev\\fastapi\_google\_starter\\models.py
```python
from sqlmodel import SQLModel, Field

class User(SQLModel, table=True):
    email: str = Field(primary_key=True)
    name: str
```

## C:\\dev\\fastapi\_google\_starter\\user\_provisioner.py
```python
from sqlmodel import Session
from models import User

class UserProvisioner:
    def __init__(self, engine):
        self.engine = engine

    def provision_user(self, email: str, name: str) -> None:
        with Session(self.engine) as session:
            existing_user = session.get(User, email)
            if existing_user:
                return
            new_user = User(email=email, name=name)
            session.add(new_user)
            session.commit()
```
