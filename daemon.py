import subprocess
import time
import logging
from datetime import datetime
from config import settings
from firewall import revoke_access

import os
import shelve

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

logger = logging.getLogger("audit_daemon")

class SessionTracker:
    def __init__(self):
        self.db_path = "/opt/amnezia-auth/sessions.db"

    def parse_iptables_counters(self):
        """Runs iptables-save -c and parses FORWARD chain byte counters per IP."""
        import re
        peers = {}
        try:
            result = subprocess.run(["iptables-save", "-c"], capture_output=True, text=True, check=True)
            # Regex to match: [pkts:bytes] -A FORWARD ... -s 10.0.42.5/32
            # We specifically want to match rules that grant access.
            pattern = re.compile(r'\[\d+:(\d+)\] -A FORWARD .*?-s ([\d\.]+)/32')
            
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

    def run_loop(self):
        logger.info(f"Starting Session Tracker Daemon...")
        logger.info(f"Inactivity timeout: {settings.inactivity_timeout_seconds}s, Max session: {settings.max_session_seconds}s")
        
        while True:
            current_time = datetime.now()
            peers = self.parse_iptables_counters()
            
            with shelve.open(self.db_path, writeback=True) as sessions:
                for ip, total_bytes in peers.items():
                    if ip not in sessions:
                        # New peer detected, start tracking
                        sessions[ip] = {
                            'rx_tx_total': total_bytes,
                            'last_active_time': current_time,
                            'session_start': current_time
                        }
                        continue
                    
                    session = sessions[ip]
                    
                    # Check for activity
                    if total_bytes > session['rx_tx_total']:
                        # Traffic has increased, update active time and total
                        session['rx_tx_total'] = total_bytes
                        session['last_active_time'] = current_time
                    
                    # Calculate durations
                    inactive_duration = current_time - session['last_active_time']
                    session_duration = current_time - session['session_start']
                    
                    # Check limits
                    if inactive_duration.total_seconds() > settings.inactivity_timeout_seconds:
                        logger.info(f"AUDIT_TIMEOUT_INACTIVE: IP {ip} inactive for {settings.inactivity_timeout_seconds} seconds. Revoking access.")
                        revoke_access(ip)
                        # Reset session so they have to login again
                        del sessions[ip]
                    elif session_duration.total_seconds() > settings.max_session_seconds:
                        logger.info(f"AUDIT_TIMEOUT_MAXSESSION: IP {ip} exceeded max session of {settings.max_session_seconds} seconds. Revoking access.")
                        revoke_access(ip)
                        del sessions[ip]

            time.sleep(60)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    tracker = SessionTracker()
    tracker.run_loop()
