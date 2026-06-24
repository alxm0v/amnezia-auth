import os
import json
import io
import base64
import pyotp
import qrcode
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from config import settings
from firewall import grant_access
import logging

logger = logging.getLogger("audit")

router = APIRouter()

# Note: templates must exist in templates/ directory
templates = Jinja2Templates(directory="templates")

def load_secrets():
    if os.path.exists(settings.totp_secrets_file):
        with open(settings.totp_secrets_file, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_secrets(secrets):
    # Ensure dir exists
    os.makedirs(os.path.dirname(settings.totp_secrets_file), exist_ok=True)
    with open(settings.totp_secrets_file, "w") as f:
        json.dump(secrets, f)

def get_client_ip(request: Request):
    client_ip = request.headers.get('x-forwarded-for', request.client.host)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()
    return client_ip

@router.get("/")
async def totp_home(request: Request):
    user = request.session.get('user')
    if user:
        return RedirectResponse(url="/success")

    client_ip = get_client_ip(request)
    secrets = load_secrets()
    
    if client_ip not in secrets:
        # Generate new secret
        secret = request.session.get('pending_totp_secret')
        if not secret:
            secret = pyotp.random_base32()
            request.session['pending_totp_secret'] = secret
            
        # Generate QR code
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=f"VPN ({client_ip})", issuer_name="AmneziaWG Portal")
        
        qr = qrcode.make(uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        
        return templates.TemplateResponse("totp_setup.html", {"request": request, "qr_b64": qr_b64, "secret": secret})
    else:
        return templates.TemplateResponse("totp_login.html", {"request": request})

@router.post("/totp-login")
async def totp_login(request: Request, code: str = Form(...)):
    client_ip = get_client_ip(request)
    secrets = load_secrets()
    secret = secrets.get(client_ip)
    
    is_setup = False
    if not secret:
        # Check pending secret
        secret = request.session.get('pending_totp_secret')
        is_setup = True
        if not secret:
            return RedirectResponse(url="/", status_code=303)

    totp = pyotp.TOTP(secret)
    # verify allows 1 window before/after to handle slight clock skew
    if totp.verify(code, valid_window=1):
        if is_setup:
            secrets[client_ip] = secret
            save_secrets(secrets)
            request.session.pop('pending_totp_secret', None)
            logger.info(f"AUDIT_TOTP_ENROLL: IP {client_ip} enrolled TOTP.")
        
        # Logged in successfully
        request.session['user'] = {'sub': f"totp_user_{client_ip}"}
        logger.info(f"AUDIT_LOGIN_SUCCESS: User from IP {client_ip} authenticated via TOTP.")
        grant_access(client_ip)
        return RedirectResponse(url="/success", status_code=303)
    else:
        # Invalid code
        logger.info(f"AUDIT_LOGIN_ERROR: Invalid TOTP code from IP {client_ip}.")
        if is_setup:
            return HTMLResponse("<h2>Invalid Code</h2><p>Please go back and try again.</p><a href='/'>Back</a>")
        else:
            return templates.TemplateResponse("totp_login.html", {"request": request, "error": "Invalid code. Please try again."})
