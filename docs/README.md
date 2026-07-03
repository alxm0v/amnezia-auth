# AmneziaWG Captive Portal

![AI Co-authored](https://img.shields.io/badge/AI-Co--Authored-blueviolet?style=for-the-badge&logo=openai&logoColor=white)

This project provides a Captive Portal authentication layer and session management daemon for AmneziaWG (WireGuard with obfuscation).

It is designed to be fully manageable via Infrastructure as Code (Ansible) and integrates with any standard OIDC provider (like Authelia, Keycloak, Authentik).

## Architecture

The system consists of three main components:
1. **AmneziaWG Server**: Provides the encrypted VPN tunnel. Traffic is blocked by default until authenticated.
2. **Captive Portal Web Service (FastAPI)**: An OIDC client running as an unprivileged user. Users navigate to the portal through the VPN and authenticate. Upon successful login, it requests the daemon to grant access.
3. **Session Tracker & Firewall Daemon**: An isolated background process with strictly limited `sudo` privileges. It modifies the `AMNEZIA_AUTH` iptables chain to grant access, monitors for network activity, and automatically revokes access for inactive peers.

**Note on Access Control**: The Captive Portal manages *authentication* (sessions), but granular *authorization* (which subnets a user can access) is managed statically by Ansible. See [FIREWALL.md](FIREWALL.md) for details on the network access control architecture.

## Deployment

The entire stack is deployed using the provided Ansible role.

1. Ensure your target server has Ubuntu/Debian installed.
2. Copy the `.example` variable files in `ansible/group_vars/vpn_servers/` and `ansible/inventory.yml.example`, removing the `.example` extension.
3. Configure your server IP/connection details in `ansible/inventory.yml`.
4. Configure your OIDC settings in `ansible/group_vars/vpn_servers/vars.yml`.
5. Configure your users/peers in `ansible/group_vars/vpn_servers/peers.yml`.
6. Define your secure cryptographic keys in `ansible/group_vars/vpn_servers/vault.yml` and **encrypt the file**:
   ```bash
   ansible-vault encrypt ansible/group_vars/vpn_servers/vault.yml
   ```
7. Run the playbook (you will be prompted for the vault password):

```bash
cd ansible
ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass
```

## Development & Security (Git Hooks)

To prevent accidental commits of secrets (like unencrypted vault files or WireGuard private keys), this repository includes a standalone pre-commit hook powered by Gitleaks. 
Before making your first commit, enable the hook:
```bash
git config core.hooksPath scripts
```

## Security & Auditing (PCI DSS)

The project provides dual-level auditing configured via `logging_settings` in `vars.yml`:
1. **Captive Portal Audit Logs** (`enable_audit_logging: true`): Tracks authentication events, session timeouts, and periodic WireGuard handshakes. Written to `/var/log/amnezia-auth/audit.log` for SIEM integration.
2. **Network Connection Logs** (`enable_kernel_connection_logging: true`): Tracks all new outgoing TCP/UDP flows initiated through the VPN. This is managed directly by the Linux kernel via iptables `LOG` target and written to the kernel ring buffer (`dmesg` / `/var/log/syslog`).
