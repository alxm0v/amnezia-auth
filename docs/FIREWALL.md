# Network Access Control Architecture

This document describes how firewall rules and network access are managed in the AmneziaWG Captive Portal.

## Separation of Concerns

The project splits access control into two distinct layers:
1. **Authentication (Dynamic)**: Managed by the Python Captive Portal & Daemon. It tracks whether a user has a valid, active session.
2. **Authorization (Static)**: Managed by Ansible. It defines which subnets the user is allowed or forbidden to access once they are authenticated.

## The 3-Tier iptables Architecture

When a packet arrives from a VPN client, it traverses the `FORWARD` chain through three layers:

### Layer 1: `FORWARD` Chain (The Entrypoint)
- **Pre-Auth**: Allows access to global pre-auth subnets (e.g., DNS, OIDC Provider IPs) defined in `preauth_allowed_subnets`.
- **Gatekeeper**: Forwards all other traffic from the VPN subnet to the `AMNEZIA_AUTH` chain.
- **Default Drop**: If a packet returns from `AMNEZIA_AUTH` without being accepted, it is dropped.

### Layer 2: `AMNEZIA_AUTH` Chain (The Session Gate)
This chain is managed **dynamically** by the Python `amnezia-auth` service.
- When a user logs in successfully, their IP is added to this chain: `-A AMNEZIA_AUTH -s <IP> -j VPN_RULES`.
- This means: "If the user is authenticated, forward their traffic to `VPN_RULES` for granular checks."
- When the session times out, the daemon deletes this rule, instantly cutting off all access.

### Layer 3: `VPN_RULES` Chain (The Authorization Layer)
This chain is managed **statically** by Ansible during deployment. It evaluates traffic for authenticated users.

Rules are applied in the following strict priority order (top to bottom):
1. **Individual User Deny**: Blocks specific subnets for a specific user (defined in `vpn_peers[].iptables_rules.deny`).
2. **Individual User Allow**: Allows specific subnets for a specific user (defined in `vpn_peers[].iptables_rules.allow`).
3. **Global Deny**: Blocks specific subnets for everyone (defined in `iptables_global_rules.deny`).
4. **Global Allow**: Allows specific subnets for everyone (defined in `iptables_global_rules.allow`).
5. **Default Policy**: A fallback rule applied to any traffic that didn't match the above lists (defined by `iptables_default_policy`, usually `DROP` or `ACCEPT`).

## Examples

### Scenario A: "Zero Trust" (Default Deny)
You want to block all access by default, but allow access to specific services.

```yaml
# ansible/group_vars/vpn_servers/vars.yml
iptables_default_policy: DROP

iptables_global_rules:
  allow:
    - 10.0.0.53/32 # Everyone can access the internal DNS
  deny: []

vpn_peers:
  - name: "alice-admin"
    ip: "10.0.42.5"
    public_key: "..."
    iptables_rules:
      allow:
        - 10.0.0.0/16 # Alice gets access to the whole VPC
```

### Scenario B: "Corporate VPN" (Default Allow)
You want to allow access to the entire VPC by default, but restrict certain users from touching sensitive databases.

```yaml
# ansible/group_vars/vpn_servers/vars.yml
iptables_default_policy: ACCEPT

iptables_global_rules:
  allow: []
  deny:
    - 10.0.99.0/24 # Block the ultra-secure HR subnet for everyone by default

vpn_peers:
  - name: "bob-contractor"
    ip: "10.0.42.6"
    public_key: "..."
    iptables_rules:
      deny:
        - 10.0.0.0/8 # Bob is a contractor, he gets blocked from EVERYTHING...
      allow:
        - 10.0.5.15/32 # ...except this one specific staging server.
```

*Note: Since individual `deny` is evaluated before individual `allow`, if a subnet overlaps, the `deny` takes precedence.*
