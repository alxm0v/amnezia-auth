import logging
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from config import settings
from firewall import grant_access, revoke_access

import os

log_dir = "/var/log/amnezia-auth"
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{log_dir}/audit.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("audit")

app = FastAPI(title="AmneziaWG Captive Portal")

# Session middleware is required for authlib
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

oauth = OAuth()
oauth.register(
    name='authelia',
    client_id=settings.oidc_client_id,
    client_secret=settings.oidc_client_secret,
    server_metadata_url=settings.oidc_discovery_url,
    client_kwargs={
        'scope': 'openid profile email groups'
    }
)

@app.get("/")
async def home(request: Request):
    user = request.session.get('user')
    if user:
        subnets_html = "".join([f"<li>{s}</li>" for s in settings.allowed_subnets_list])
        return HTMLResponse(
            f"<h2>Authentication Successful</h2>"
            f"<p>You now have access to the following subnets:</p>"
            f"<ul>{subnets_html}</ul>"
            f"<a href='/logout'>Logout</a>"
        )
    return HTMLResponse(
        "<h2>VPN Captive Portal</h2>"
        "<p>Please login to access the network.</p>"
        "<a href='/login'>Login with Authelia</a>"
    )

@app.get("/login")
async def login(request: Request):
    # The redirect URI should be the absolute URL to the /auth endpoint
    redirect_uri = str(request.url_for('auth'))
    # Ensure redirect_uri uses https if deployed behind Traefik, or trust proxy
    if "http://" in redirect_uri and request.headers.get("x-forwarded-proto") == "https":
        redirect_uri = redirect_uri.replace("http://", "https://")
        
    return await oauth.authelia.authorize_redirect(request, redirect_uri)

@app.get("/auth")
async def auth(request: Request):
    try:
        token = await oauth.authelia.authorize_access_token(request)
        user = token.get('userinfo')
        if user:
            request.session['user'] = dict(user)
            client_ip = request.headers.get('x-forwarded-for', request.client.host)
            if client_ip and ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
                
            username = user.get('preferred_username', user.get('sub'))
            logger.info(f"AUDIT_LOGIN_SUCCESS: User '{username}' successfully authenticated from IP {client_ip}")
            grant_access(client_ip)
            return RedirectResponse(url="/")
    except Exception as e:
        logger.error(f"AUDIT_LOGIN_ERROR: OIDC Auth error: {e}")
        return HTMLResponse("<h2>Authentication Failed</h2><a href='/login'>Try Again</a>")
    
    return RedirectResponse(url="/login")

@app.get("/logout")
async def logout(request: Request):
    client_ip = request.headers.get('x-forwarded-for', request.client.host)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    request.session.pop('user', None)
    logger.info(f"AUDIT_LOGOUT: User logged out manually from IP {client_ip}")
    revoke_access(client_ip)
    return RedirectResponse(url="/")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=True)
