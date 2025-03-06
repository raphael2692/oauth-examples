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
from contextlib import asynccontextmanager

app = FastAPI()

templates = Jinja2Templates(directory="templates")
# Database setup
DATABASE_URL = "sqlite:///./database.db"
engine = create_engine(DATABASE_URL)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    create_db_and_tables()
    yield
    # Shutdown
    # Perform any cleanup if needed

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
    
    auth_result = await auth_provider.process_callback(code)  # Await the async method
    if not auth_result:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    user_email = auth_result.user.email
    user_name = auth_result.user.name or ""
    
    if not user_email:
        raise HTTPException(status_code=400, detail="Email not provided by the provider.")
    
    # Provision user (consider making this async if using async database driver)
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