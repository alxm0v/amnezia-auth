import subprocess
import logging
from config import settings

logger = logging.getLogger(__name__)

def grant_access(ip: str):
    """Adds an iptables rule to allow the IP address to forward traffic."""
    logger.info(f"Granting network access to {ip}")
    try:
        # Check if rule already exists to avoid duplicates
        check = subprocess.run(["iptables", "-C", "AMNEZIA_AUTH", "-s", ip, "-j", "VPN_RULES"], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check.returncode != 0:
            subprocess.run(["iptables", "-A", "AMNEZIA_AUTH", "-s", ip, "-j", "VPN_RULES"], check=True)
            logger.info(f"Successfully granted access to {ip}")
        else:
            logger.info(f"Access already granted for {ip}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to grant access to {ip}: {e}")

def check_access(ip: str) -> bool:
    """Checks if the IP address currently has an iptables rule granting access."""
    try:
        check = subprocess.run(["iptables", "-C", "AMNEZIA_AUTH", "-s", ip, "-j", "VPN_RULES"], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return check.returncode == 0
    except Exception as e:
        logger.error(f"Error checking access for {ip}: {e}")
        return False

def revoke_access(ip: str):
    """Removes the iptables rule for the IP address."""
    logger.info(f"Revoking network access for {ip}")
    try:
        while True:
            # We loop because there could be multiple identical rules if something went wrong
            res = subprocess.run(["iptables", "-D", "AMNEZIA_AUTH", "-s", ip, "-j", "VPN_RULES"], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode != 0:
                break
        logger.info(f"Successfully revoked access for {ip}")
    except Exception as e:
        logger.error(f"Error during revoke access for {ip}: {e}")
