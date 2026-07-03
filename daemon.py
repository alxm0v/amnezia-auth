import subprocess
import time
import logging
from datetime import datetime
from config import settings
import os
import shelve
import asyncio
from fastapi import FastAPI, HTTPException
import uvicorn

log_dir = "/var/log/amnezia-auth"
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{log_dir}/daemon.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("audit_daemon")

audit_logger = logging.getLogger("audit_external")
audit_logger.setLevel(logging.INFO)
if not audit_logger.handlers:
    audit_handler = logging.FileHandler(f"{log_dir}/audit.log")
    audit_handler.setFormatter(logging.Formatter('%(asctime)s - audit - %(levelname)s - %(message)s'))
    audit_logger.addHandler(audit_handler)

app = FastAPI(title="AmneziaWG Auth Daemon API")

# Sudo wrappers for firewall management
def daemon_grant_access(ip: str):
    subprocess.run(["sudo", "-n", "/sbin/iptables", "-I", "AMNEZIA_AUTH", "-s", f"{ip}/32", "-j", "ACCEPT"], check=False)
    logger.debug(f"Granting network access to {ip}")

def daemon_revoke_access(ip: str):
    subprocess.run(["sudo", "-n", "/sbin/iptables", "-D", "AMNEZIA_AUTH", "-s", f"{ip}/32", "-j", "ACCEPT"], check=False)
    logger.debug(f"Revoking network access for {ip}")

def daemon_check_access(ip: str) -> bool:
    result = subprocess.run(["sudo", "-n", "/sbin/iptables", "-C", "AMNEZIA_AUTH", "-s", f"{ip}/32", "-j", "ACCEPT"], capture_output=True)
    return result.returncode == 0

@app.post("/grant")
def api_grant(ip: str):
    if not daemon_check_access(ip):
        daemon_grant_access(ip)
    return {"status": "ok"}

@app.post("/revoke")
def api_revoke(ip: str):
    if daemon_check_access(ip):
        daemon_revoke_access(ip)
    return {"status": "ok"}

@app.get("/check")
def api_check(ip: str):
    return {"access": daemon_check_access(ip)}

class WireGuardTracker:
    def __init__(self):
        self.db_path = settings.handshakes_db_path
        self.peer_names = self._parse_peer_names()

    def _parse_peer_names(self):
        """Parses awg0.conf to map AllowedIPs to Peer Names via sudo cat."""
        peers = {}
        try:
            result = subprocess.run(["sudo", "-n", "/bin/cat", "/etc/amnezia/amneziawg/awg0.conf"], capture_output=True, text=True, check=True)
            lines = result.stdout.split('\n')
            
            current_name = "Unknown"
            for line in lines:
                line = line.strip()
                if line.startswith("# ") and not line.startswith("# Post"):
                    current_name = line[2:]
                elif line.startswith("AllowedIPs"):
                    parts = line.split("=")
                    if len(parts) == 2:
                        ip_cidr = parts[1].strip()
                        ip = ip_cidr.split("/")[0]
                        peers[ip] = current_name
        except Exception as e:
            logger.error(f"Failed to parse awg0.conf: {e}")
        return peers

    def check_handshakes(self):
        try:
            result = subprocess.run(["sudo", "-n", "/usr/bin/awg", "show", "awg0", "dump"], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            
            with shelve.open(self.db_path, writeback=True) as db:
                for line in lines:
                    parts = line.split('\t')
                    if len(parts) < 8:
                        continue
                    
                    endpoint = parts[2]
                    allowed_ips = parts[3]
                    latest_handshake = int(parts[4])
                    
                    if endpoint == "(none)" or latest_handshake == 0:
                        continue
                        
                    ip = allowed_ips.split("/")[0]
                    peer_name = self.peer_names.get(ip, "Unknown")
                    public_ip = endpoint.split(":")[0]
                    
                    if ip not in db:
                        if settings.enable_audit_logging:
                            logger.info(f"AUDIT_VPN_HANDSHAKE: Peer '{peer_name}' ({ip}) connected from Public IP {public_ip}")
                            audit_logger.info(f"AUDIT_VPN_HANDSHAKE: Peer '{peer_name}' ({ip}) connected from Public IP {public_ip}")
                        db[ip] = {'handshake': latest_handshake, 'endpoint': public_ip}
                    else:
                        saved = db[ip]
                        time_diff = latest_handshake - saved['handshake']
                        if time_diff > settings.handshake_silence_threshold_seconds or saved['endpoint'] != public_ip:
                            if settings.enable_audit_logging:
                                logger.info(f"AUDIT_VPN_HANDSHAKE: Peer '{peer_name}' ({ip}) connected from Public IP {public_ip}")
                                audit_logger.info(f"AUDIT_VPN_HANDSHAKE: Peer '{peer_name}' ({ip}) connected from Public IP {public_ip}")
                            db[ip] = {'handshake': latest_handshake, 'endpoint': public_ip}
        except Exception as e:
            logger.error(f"Failed to check handshakes: {e}")

class SessionTracker:
    def __init__(self):
        self.db_path = settings.sessions_db_path

    def parse_iptables_counters(self):
        """Runs iptables-save -c and parses AMNEZIA_AUTH chain byte counters per IP."""
        import re
        peers = {}
        try:
            result = subprocess.run(["sudo", "-n", "/sbin/iptables-save", "-c"], capture_output=True, text=True, check=True)
            pattern = re.compile(r'\[\d+:(\d+)\] -A AMNEZIA_AUTH .*?-s ([\d\.]+)/32')
            
            for line in result.stdout.strip().split('\n'):
                match = pattern.search(line)
                if match:
                    bytes_count = int(match.group(1))
                    ip = match.group(2)
                    
                    if ip in peers:
                        peers[ip] += bytes_count
                    else:
                        peers[ip] = bytes_count
        except Exception as e:
            logger.error(f"Failed to get iptables dump: {e}")
        return peers

    async def run_loop(self):
        logger.info(f"Starting Session Tracker Daemon API...")
        logger.info(f"Inactivity timeout: {settings.inactivity_timeout_seconds}s, Max session: {settings.max_session_seconds}s")
        
        wg_tracker = WireGuardTracker()
        
        while True:
            current_time = datetime.now()
            # Run blocking operations in thread
            peers = await asyncio.to_thread(self.parse_iptables_counters)
            await asyncio.to_thread(wg_tracker.check_handshakes)
            
            def update_sessions():
                with shelve.open(self.db_path, writeback=True) as sessions:
                    for ip, total_bytes in peers.items():
                        if ip not in sessions:
                            sessions[ip] = {
                                'rx_tx_total': total_bytes,
                                'last_active_time': current_time,
                                'session_start': current_time
                            }
                            continue
                        
                        session = sessions[ip]
                        
                        if total_bytes < session['rx_tx_total']:
                            session['rx_tx_total'] = total_bytes
                            session['last_active_time'] = current_time
                            session['session_start'] = current_time
                        elif total_bytes > session['rx_tx_total']:
                            session['rx_tx_total'] = total_bytes
                            session['last_active_time'] = current_time
                        
                        inactive_duration = current_time - session['last_active_time']
                        session_duration = current_time - session['session_start']
                        
                        if inactive_duration.total_seconds() > settings.inactivity_timeout_seconds:
                            if settings.enable_audit_logging:
                                logger.info(f"AUDIT_TIMEOUT_INACTIVE: IP {ip} inactive for {settings.inactivity_timeout_seconds} seconds. Revoking access.")
                                audit_logger.info(f"AUDIT_TIMEOUT_INACTIVE: IP {ip} inactive for {settings.inactivity_timeout_seconds} seconds. Revoking access.")
                            daemon_revoke_access(ip)
                            del sessions[ip]
                        elif session_duration.total_seconds() > settings.max_session_seconds:
                            if settings.enable_audit_logging:
                                logger.info(f"AUDIT_TIMEOUT_MAXSESSION: IP {ip} exceeded max session of {settings.max_session_seconds} seconds. Revoking access.")
                                audit_logger.info(f"AUDIT_TIMEOUT_MAXSESSION: IP {ip} exceeded max session of {settings.max_session_seconds} seconds. Revoking access.")
                            daemon_revoke_access(ip)
                            del sessions[ip]

            await asyncio.to_thread(update_sessions)
            await asyncio.sleep(60)

tracker = SessionTracker()

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(tracker.run_loop())

if __name__ == "__main__":
    uvicorn.run("daemon:app", host="127.0.0.1", port=9000, reload=False)
