import logging
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from config import settings
from firewall import grant_access, revoke_access, check_access

import os

log_dir = "/var/log/amnezia-auth"
try:
    os.makedirs(log_dir, exist_ok=True)
except PermissionError:
    pass

log_handlers = [logging.StreamHandler()]
if os.path.exists(log_dir):
    log_handlers.append(logging.FileHandler(f"{log_dir}/uvicorn.log"))

# Configure root logger (for Uvicorn, httpx, and general app logs)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)

# Configure dedicated audit logger
logger = logging.getLogger("audit")
logger.propagate = False  # Prevent audit logs from duplicating into uvicorn.log
if os.path.exists(log_dir):
    audit_handler = logging.FileHandler(f"{log_dir}/audit.log")
    audit_handler.setFormatter(logging.Formatter('%(asctime)s - audit - %(levelname)s - %(message)s'))
    logger.addHandler(audit_handler)

app = FastAPI(title="AmneziaWG Captive Portal")

# Session middleware is required for authlib
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

# Shared Success Page
@app.get("/success")
async def success_page(request: Request):
    user = request.session.get('user')
    authenticated = request.session.get('authenticated')
    client_ip = request.client.host
    if settings.use_reverse_proxy:
        xff = request.headers.get('x-forwarded-for')
        if xff:
            client_ip = xff.split(',')[0].strip()
        
    if not (user or authenticated):
        if check_access(client_ip):
            revoke_access(client_ip)
        return RedirectResponse(url="/")

    if not check_access(client_ip):
        # Daemon revoked access due to timeout, or server rebooted
        request.session.clear()
        return RedirectResponse(url="/")

    return HTMLResponse(
        f"<h2>Authentication Successful</h2>"
        f"<p>Your session is active. You may now access the internal network.</p>"
        f"<a href='/logout'>Logout</a>"
    )

@app.get("/logout")
async def logout(request: Request):
    client_ip = request.client.host
    if settings.use_reverse_proxy:
        xff = request.headers.get('x-forwarded-for')
        if xff:
            client_ip = xff.split(',')[0].strip()

    request.session.clear()
    logger.info(f"AUDIT_LOGOUT: User logged out manually from IP {client_ip}")
    revoke_access(client_ip)
    return RedirectResponse(url="/")

if settings.auth_mode == "totp":
    # Dynamically import totp routes to avoid dependencies when not used
    from totp_routes import router as totp_router
    app.include_router(totp_router)
else:
    # OIDC setup
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
        client_ip = request.client.host
        if settings.use_reverse_proxy:
            xff = request.headers.get('x-forwarded-for')
            if xff:
                client_ip = xff.split(',')[0].strip()
            
        if user:
            if not check_access(client_ip):
                request.session.clear()
                return RedirectResponse(url="/")
            return RedirectResponse(url="/success")
            
        if check_access(client_ip):
            revoke_access(client_ip)
            
        return HTMLResponse(
            "<h2>VPN Captive Portal</h2>"
            "<p>Please login to access the network.</p>"
            "<a href='/login'>Login with Authelia</a>"
        )

    @app.get("/login")
    async def login(request: Request):
        redirect_uri = str(request.url_for('auth'))
        if "http://" in redirect_uri and request.headers.get("x-forwarded-proto") == "https":
            redirect_uri = redirect_uri.replace("http://", "https://")
        return await oauth.authelia.authorize_redirect(request, redirect_uri)

    @app.get("/auth")
    async def auth(request: Request):
        try:
            token = await oauth.authelia.authorize_access_token(request)
            user = token.get('userinfo')
            
            if user:
                # If only 'sub' is present (common in ID tokens), fetch full profile from UserInfo endpoint
                if 'preferred_username' not in user and 'name' not in user and 'email' not in user:
                    try:
                        full_user = await oauth.authelia.userinfo(token=token)
                        if full_user:
                            # user is usually an authlib UserInfo object, converting to dict
                            user = dict(user)
                            user.update(dict(full_user))
                    except Exception as e:
                        logger.warning(f"Failed to fetch full userinfo from OIDC provider: {e}")

                logger.debug(f"OIDC_DEBUG_USERINFO: {dict(user)}")
                request.session['user'] = dict(user)
                
                client_ip = request.client.host
                if settings.use_reverse_proxy:
                    xff = request.headers.get('x-forwarded-for')
                    if xff:
                        client_ip = xff.split(',')[0].strip()
                    
                username = user.get('preferred_username') or user.get('name') or user.get('email') or user.get('sub')
                logger.info(f"AUDIT_LOGIN_SUCCESS: User '{username}' successfully authenticated from IP {client_ip}")
                grant_access(client_ip)
                return RedirectResponse(url="/success")
        except Exception as e:
            logger.error(f"AUDIT_LOGIN_ERROR: OIDC Auth error: {e}")
            return HTMLResponse("<h2>Authentication Failed</h2><a href='/login'>Try Again</a>")
        
        return RedirectResponse(url="/login")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=True)
