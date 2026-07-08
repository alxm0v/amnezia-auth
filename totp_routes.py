import os
import json
import io
import base64
import pyotp
import qrcode
from filelock import FileLock
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from config import settings
from firewall import grant_access, check_access
import logging

logger = logging.getLogger("audit")

router = APIRouter()

# Note: templates must exist in templates/ directory
templates = Jinja2Templates(directory="templates")

def load_secrets():
    lock = FileLock(settings.totp_secrets_file + ".lock")
    with lock:
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
    lock = FileLock(settings.totp_secrets_file + ".lock")
    with lock:
        with open(settings.totp_secrets_file, "w") as f:
            json.dump(secrets, f)

def get_client_ip(request: Request):
    client_ip = request.client.host
    if settings.use_reverse_proxy:
        xff = request.headers.get('x-forwarded-for')
        if xff:
            client_ip = xff.split(',')[0].strip()
    return client_ip

def get_peer_name(ip):
    try:
        conf_path = f"/etc/amnezia/amneziawg/{settings.vpn_interface}.conf"
        with open(conf_path, "r") as f:
            lines = f.readlines()
        
        current_name = "Unknown"
        for line in lines:
            line = line.strip()
            if line.startswith("# ") and not line.startswith("# Post") and not line.startswith("# Pre"):
                current_name = line[2:]
            elif line.startswith(f"AllowedIPs = {ip}/"):
                return current_name
    except Exception as e:
        logger.error(f"Failed to parse peer name for {ip}: {e}")
    return "Unknown"

@router.get("/")
async def totp_home(request: Request):
    client_ip = get_client_ip(request)
    user = request.session.get('user')
    
    # If the user has a cookie session, they are authenticated
    if user:
        if not check_access(client_ip):
            request.session.clear()
            return RedirectResponse(url="/")
        return RedirectResponse(url="/success")
        
    # User has no session cookie. If firewall is open, revoke it (session is source of truth).
    if check_access(client_ip):
        revoke_access(client_ip)
    secrets = load_secrets()
    
    if client_ip not in secrets:
        # Generate new secret
        secret = request.session.get('pending_totp_secret')
        if not secret:
            secret = pyotp.random_base32()
            request.session['pending_totp_secret'] = secret
            
        # Generate QR code
        totp = pyotp.TOTP(secret)
        peer_name = get_peer_name(client_ip)
        account_name = settings.totp_account_name_template.format(peer_name=peer_name, peer_ip=client_ip)
        uri = totp.provisioning_uri(name=account_name, issuer_name=settings.totp_issuer_name)
        
        qr = qrcode.make(uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        
        return templates.TemplateResponse(request=request, name="totp_setup.html", context={"qr_b64": qr_b64, "secret": secret})
    else:
        return templates.TemplateResponse(request=request, name="totp_login.html")

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
            return templates.TemplateResponse(request=request, name="totp_login.html", context={"error": "Invalid code. Please try again."})
