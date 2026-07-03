import logging
import httpx
from fastapi import HTTPException

logger = logging.getLogger("audit")

DAEMON_URL = "http://127.0.0.1:9000"

def grant_access(ip):
    try:
        response = httpx.post(f"{DAEMON_URL}/grant", params={"ip": ip}, timeout=5.0)
        response.raise_for_status()
        logger.info(f"AUDIT_ACCESS_GRANTED: Network access successfully granted to {ip}")
    except Exception as e:
        logger.error(f"AUDIT_ERROR: Failed to communicate with daemon to grant access for {ip}: {e}")

def revoke_access(ip):
    try:
        response = httpx.post(f"{DAEMON_URL}/revoke", params={"ip": ip}, timeout=5.0)
        response.raise_for_status()
        logger.info(f"AUDIT_ACCESS_REVOKED: Network access successfully revoked for {ip}")
    except Exception as e:
        logger.error(f"AUDIT_ERROR: Failed to communicate with daemon to revoke access for {ip}: {e}")

def check_access(ip):
    try:
        response = httpx.get(f"{DAEMON_URL}/check", params={"ip": ip}, timeout=5.0)
        if response.status_code == 200:
            return response.json().get("access", False)
        return False
    except Exception as e:
        logger.error(f"Failed to check access with daemon for {ip}: {e}")
        return False
