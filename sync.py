#!/usr/bin/env python3
"""
Synchronize host names from Traefik routers to a UniFi OS device's DNS forwarder.

The script reads the list of HTTP routers via the Traefik API, extracts
hostnames from `Host()` or `HostSNI()` rules and determines the upstream IP
address for each router by inspecting its associated service.  It then
connects to a UniFi OS device via SSH, fetches the current services
configuration using `ubios‑udapi‑client`, updates the `dnsForwarder.hostRecords`
array with the discovered host/IP pairs and writes the updated JSON back via
`ubios‑udapi‑client PUT /services`.

All configuration is provided via environment variables; see README for
details.
"""

import json
import os
import re
import sys
import time
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse

import requests

try:
    import paramiko
except ImportError:
    paramiko = None  # type: ignore


def debug(msg: str) -> None:
    """Simple debug logger controlled by DEBUG env var."""
    if os.environ.get("DEBUG"):
        print(msg, file=sys.stderr)


def get_traefik_auth() -> Optional[tuple]:
    """Return a basic auth tuple if TRAEFIK_USERNAME and TRAEFIK_PASSWORD are set."""
    user = os.environ.get("TRAEFIK_USERNAME")
    password = os.environ.get("TRAEFIK_PASSWORD")
    if user and password:
        return (user, password)
    return None


def extract_hostnames(rule: str, domain_suffix: Optional[str] = None) -> List[str]:
    """
    Extract hostnames from a Traefik router rule.  Only `Host()` and
    `HostSNI()` matchers are considered.  If `domain_suffix` is provided,
    hostnames not ending in that suffix are ignored.

    The rule syntax is described in the Traefik docs; we use a simple
    regular expression to capture comma‑separated lists of hostnames inside
    backticks.  Traefik rules may contain multiple matchers combined with
    logical operators (e.g. `Host(`a.example.com`) && PathPrefix(`/api`)`).
    This function ignores everything except `Host`/`HostSNI` matchers.
    """
    hostnames: List[str] = []
    if not rule:
        return hostnames
    # Regex for Host(`foo`,`bar`), Host("foo", "bar") or HostSNI(...)
    pattern = r"HostS?NI?\s*\(([^)]*)\)"
    for match in re.finditer(pattern, rule, re.IGNORECASE):
        hosts_block = match.group(1)
        # Split by commas not inside quotes/backticks
        # Remove surrounding quotes/backticks and whitespace
        for part in re.split(r"\s*,\s*", hosts_block):
            part = part.strip().strip("`\"'")
            if not part:
                continue
            if domain_suffix and not part.endswith(domain_suffix):
                continue
            hostnames.append(part)
    return hostnames


def extract_service_ip(service: dict) -> Optional[str]:
    """
    Extract the first server IP address from a Traefik service definition.

    Services may have a simple `loadBalancer.servers` list or a more complex
    weighted configuration.  This function attempts to handle both by
    recursively looking for `servers` arrays.  The first server's URL is
    parsed and its hostname portion returned.
    """
    def find_servers(obj: dict) -> Iterable[str]:
        # Yield all URLs from any servers lists encountered
        if isinstance(obj, dict):
            if "servers" in obj and isinstance(obj["servers"], list):
                for srv in obj["servers"]:
                    url = srv.get("url")
                    if url:
                        yield url
            # Weighted services
            if "weighted" in obj and isinstance(obj["weighted"], dict):
                for wsvc in obj["weighted"].get("services", []):
                    yield from find_servers(wsvc)
            # Nested loadBalancer definitions
            for val in obj.values():
                if isinstance(val, dict):
                    yield from find_servers(val)
        return []

    for url in find_servers(service):
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            continue
    return None


def fetch_traefik_hosts() -> Dict[str, str]:
    """
    Query the Traefik API for all HTTP routers and return a mapping of
    hostname → upstream IP address.

    The function stops at the first server in each service; if a service has
    multiple servers behind a load balancer, only the first IP is used.
    """
    base_url = os.environ.get("TRAEFIK_API_URL", "http://localhost:8080/api").rstrip("/")
    domain_suffix = os.environ.get("DOMAIN_SUFFIX")
    auth = get_traefik_auth()
    try:
        resp = requests.get(f"{base_url}/http/routers", auth=auth, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error contacting Traefik API: {e}", file=sys.stderr)
        return {}
    routers = resp.json()
    hosts: Dict[str, str] = {}
    if not isinstance(routers, list):
        print("Unexpected response from Traefik API", file=sys.stderr)
        return hosts
    for router in routers:
        rule = router.get("rule")
        service_name = router.get("service")
        if not service_name or not rule:
            continue
        hostnames = extract_hostnames(rule, domain_suffix=domain_suffix)
        if not hostnames:
            continue
        # The service name may include a provider suffix (e.g. my-service@docker)
        svc_endpoint = service_name
        try:
            svc_resp = requests.get(f"{base_url}/http/services/{svc_endpoint}", auth=auth, timeout=10)
            svc_resp.raise_for_status()
        except Exception as e:
            debug(f"Failed to fetch service {svc_endpoint}: {e}")
            continue
        service_data = svc_resp.json()
        ip = extract_service_ip(service_data)
        if not ip:
            debug(f"No IP found for service {svc_endpoint}")
            continue
        for hostname in hostnames:
            hosts[hostname] = ip
    return hosts


def ssh_connect() -> Optional[paramiko.SSHClient]:
    """
    Establish an SSH connection to the UniFi OS device.  Returns a connected
    paramiko.SSHClient or None on failure.
    """
    if paramiko is None:
        print("paramiko is not installed; SSH functions are unavailable", file=sys.stderr)
        return None
    host = os.environ.get("UNIFI_SSH_HOST")
    user = os.environ.get("UNIFI_SSH_USER", "root")
    password = os.environ.get("UNIFI_SSH_PASSWORD")
    key_path = os.environ.get("UNIFI_SSH_PRIVATE_KEY")
    if not host:
        print("UNIFI_SSH_HOST is not set", file=sys.stderr)
        return None
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_path:
            key = paramiko.RSAKey.from_private_key_file(key_path)
            ssh.connect(hostname=host, username=user, pkey=key, timeout=15)
        else:
            if not password:
                print("Either UNIFI_SSH_PASSWORD or UNIFI_SSH_PRIVATE_KEY must be set", file=sys.stderr)
                return None
            ssh.connect(hostname=host, username=user, password=password, timeout=15)
    except Exception as e:
        print(f"Failed to connect to {host} via SSH: {e}", file=sys.stderr)
        return None
    return ssh


def fetch_services_json(ssh: paramiko.SSHClient) -> Optional[dict]:
    """
    Run `ubios‑udapi‑client GET -r /services` on the UniFi device and parse the
    returned JSON.  Returns the parsed dictionary or None on error.
    """
    cmd = "ubios-udapi-client GET -r /services"
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
        out = stdout.read().decode()
        err = stderr.read().decode()
    except Exception as e:
        print(f"Error running '{cmd}': {e}", file=sys.stderr)
        return None
    if err:
        debug(f"stderr from GET /services: {err.strip()}")
    try:
        return json.loads(out)
    except Exception as e:
        print(f"Failed to parse JSON from GET /services: {e}", file=sys.stderr)
        return None


def update_dns_records(services: dict, host_ip_map: Dict[str, str]) -> bool:
    """
    Update the services JSON in place with host records from `host_ip_map`.

    Returns True if any changes were made, False otherwise.
    """
    dns = services.setdefault("dnsForwarder", {})
    records: List[dict] = dns.get("hostRecords") or []
    # Build dictionary keyed by lowercased hostName
    existing: Dict[str, dict] = {rec.get("hostName", "").lower(): rec for rec in records if isinstance(rec, dict)}
    changed = False
    for host, ip in host_ip_map.items():
        key = host.lower()
        new_record = {
            "hostName": host,
            "registerNonQualified": True,
            "address": {
                "address": ip,
                "origin": None,
                "version": "v4",
            },
        }
        if key in existing:
            # Update existing record if IP changed
            rec = existing[key]
            addr = rec.get("address", {})
            if addr.get("address") != ip:
                debug(f"Updating {host} → {ip} (was {addr.get('address')})")
                existing[key] = new_record
                changed = True
        else:
            debug(f"Adding {host} → {ip}")
            existing[key] = new_record
            changed = True
    if changed:
        dns["hostRecords"] = list(existing.values())
    return changed


def push_services_json(ssh: paramiko.SSHClient, services: dict) -> bool:
    """
    Write the updated services JSON to a temporary file on the UniFi device and
    invoke `ubios‑udapi‑client PUT /services` to apply it.

    Returns True on success.
    """
    tmp_name = f"/tmp/traefik_unifi_{int(time.time())}.json"
    try:
        sftp = ssh.open_sftp()
        with sftp.file(tmp_name, "w") as f:
            f.write(json.dumps(services))
        sftp.close()
    except Exception as e:
        print(f"Failed to upload temp JSON to UniFi device: {e}", file=sys.stderr)
        return False
    cmd = f'ubios-udapi-client PUT /services "@{tmp_name}"'
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
        out = stdout.read().decode()
        err = stderr.read().decode()
        if err:
            debug(f"stderr from PUT /services: {err.strip()}")
    except Exception as e:
        print(f"Error running '{cmd}': {e}", file=sys.stderr)
        return False
    finally:
        # Always remove the temporary file
        try:
            ssh.exec_command(f'rm -f "{tmp_name}"')
        except Exception:
            pass
    return True


def sync_once() -> bool:
    """Perform a single sync run; return True on success."""
    host_ip_map = fetch_traefik_hosts()
    if not host_ip_map:
        debug("No host mappings discovered from Traefik; skipping update")
        return False
    ssh = ssh_connect()
    if ssh is None:
        return False
    try:
        services = fetch_services_json(ssh)
        if services is None:
            return False
        if not update_dns_records(services, host_ip_map):
            debug("DNS records already up to date; nothing to do")
            return True
        if not push_services_json(ssh, services):
            return False
        print(f"Updated {len(host_ip_map)} host record(s) on UniFi device")
        return True
    finally:
        ssh.close()


def main() -> None:
    interval = os.environ.get("SYNC_INTERVAL")
    if interval:
        try:
            interval_sec = int(interval)
        except ValueError:
            print("Invalid SYNC_INTERVAL; must be integer seconds", file=sys.stderr)
            sys.exit(1)
        while True:
            try:
                sync_once()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Unexpected error during sync: {e}", file=sys.stderr)
            time.sleep(max(1, interval_sec))
    else:
        success = sync_once()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()