import subprocess
import logging
from config import settings

logger = logging.getLogger(__name__)

def grant_access(ip: str):
    """Adds an iptables rule to allow the IP address to forward traffic."""
    logger.info(f"Granting network access to {ip}")
    subnets = settings.allowed_subnets_list
    iface = settings.vpn_interface
    for dest in subnets:
        try:
            # Check if rule already exists to avoid duplicates
            check = subprocess.run(["iptables", "-C", "FORWARD", "-i", iface, "-s", ip, "-d", dest, "-j", "ACCEPT"], 
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check.returncode != 0:
                subprocess.run(["iptables", "-I", "FORWARD", "1", "-i", iface, "-s", ip, "-d", dest, "-j", "ACCEPT"], check=True)
                logger.info(f"Successfully granted access to {ip} for destination {dest}")
            else:
                logger.info(f"Access already granted for {ip} to {dest}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to grant access to {ip} for {dest}: {e}")

def revoke_access(ip: str):
    """Removes the iptables rule for the IP address."""
    logger.info(f"Revoking network access for {ip}")
    subnets = settings.allowed_subnets_list
    iface = settings.vpn_interface
    for dest in subnets:
        try:
            while True:
                # We loop because there could be multiple identical rules if something went wrong
                res = subprocess.run(["iptables", "-D", "FORWARD", "-i", iface, "-s", ip, "-d", dest, "-j", "ACCEPT"], 
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if res.returncode != 0:
                    break
            logger.info(f"Successfully revoked access for {ip} to {dest}")
        except Exception as e:
            logger.error(f"Error during revoke access for {ip} to {dest}: {e}")
