from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from auth_provider import AuthProvider, MicrosoftAuth, GoogleAuth
import os
from typing import Optional
from decouple import config

app = FastAPI()

templates = Jinja2Templates(directory="templates")

def get_auth_provider(provider_name: str) -> AuthProvider:
    """Factory function to create auth provider instances"""
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
    # Validate state parameter
    stored_state = request.cookies.get("oauth_state")
    if not stored_state or stored_state != state:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    try:
        auth_provider = get_auth_provider(provider)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing")
    
    # Process authentication callback
    auth_result = auth_provider.process_callback(code)
    if not auth_result:
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    # Create response and set user cookies
    response = RedirectResponse(url="/")
    response.set_cookie("user_email", auth_result.user.email or "", path="/")
    response.set_cookie("user_name", auth_result.user.name or "", path="/")
    
    # Clear the state cookie
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