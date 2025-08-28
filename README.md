# Traefik → UniFi Sync

This project provides a simple container and Python script to synchronize the host
names configured in your Traefik instance with the local DNS forwarder on a
UniFi OS device (e.g. UDM, UDM‑Pro or other UniFi gateways).  It is intended
for home labs or small environments where you already rely on Traefik for
reverse‑proxy routing and would like to automatically create matching DNS
records on your UniFi gateway so that clients on your LAN can resolve the same
hostnames.

> **Note**
>
> UniFi’s official API currently exposes limited functionality for managing
> custom DNS records.  On UniFi OS devices the DNS forwarder uses a
> `dnsForwarder.hostRecords` array stored in the services configuration.  As
> described in the [udm‑host‑records documentation](https://github.com/evaneaston/udm-host-records),
> you can add or modify these records by **GET**‑ting the `/services` endpoint,
> updating `dnsForwarder.hostRecords` and **PUT**‑ting the modified JSON back to
> `/services`【614892259740449†L272-L281】.  This script uses that same
> mechanism.

## How it works

1. **Read routers from Traefik:**  The script queries the Traefik API to
   discover all HTTP routers.  Traefik exposes its configuration through
   endpoints under `/api/`—for example, `/api/http/routers` returns a list of
   HTTP routers and `/api/http/services/{name}` returns the associated
   service【4092618426293†L430-L437】.  The script parses each router’s `rule`
   and extracts host names from `Host(...)` or `HostSNI(...)` expressions.
   It then looks up the corresponding service to determine the upstream IP
   address and builds a mapping of host name → IP address.

2. **Update UniFi DNS host records:**  Using SSH the script connects to your
   UniFi OS device and runs `ubios‑udapi‑client GET -r /services` to fetch the
   current services configuration.  It updates the `dnsForwarder.hostRecords`
   array with the host/IP pairs discovered from Traefik and then writes the
   updated JSON back to the device using `ubios‑udapi‑client PUT /services`.
   Changes take effect immediately and persist across reboots【614892259740449†L272-L289】.

3. **Run as a container:**  A `Dockerfile` is provided to build a small
   container around this script.  You can run it manually or deploy it as a
   swarm service.  All configuration is provided through environment variables
   so that secrets can be managed via Docker secrets or Swarm configs.

## Requirements

* A running Traefik instance with its API exposed (e.g. by enabling the
  dashboard).  The API must be reachable from within the container.  Consult
  the [Traefik API & dashboard documentation](https://doc.traefik.io/traefik/reference/install-configuration/api-dashboard/)
  for details on enabling and securing the `/api` endpoints.
* A UniFi OS device (UDM, UDM‑Pro, UXG, etc.) with SSH enabled.  The
  `ubios‑udapi‑client` utility must be available on the device (this is the
  case on UniFi OS).  The user account used for SSH must have permission to
  run `ubios‑udapi‑client`.

## Configuration

All configuration is done via environment variables.  The most important
variables are:

| Variable                 | Description                                                                                              |
|--------------------------|----------------------------------------------------------------------------------------------------------|
| `TRAEFIK_API_URL`        | Base URL of the Traefik API (e.g. `http://traefik:8080/api`).                                            |
| `TRAEFIK_USERNAME`       | Optional HTTP basic auth username for the Traefik API.                                                   |
| `TRAEFIK_PASSWORD`       | Optional HTTP basic auth password for the Traefik API.                                                   |
| `UNIFI_SSH_HOST`         | Hostname or IP address of your UniFi OS device.                                                          |
| `UNIFI_SSH_USER`         | SSH username (defaults to `root`).                                                                       |
| `UNIFI_SSH_PASSWORD`     | SSH password (if using password authentication).                                                          |
| `UNIFI_SSH_PRIVATE_KEY`  | Path to a private key file inside the container (if using key authentication).                           |
| `SYNC_INTERVAL`          | Optional number of seconds between syncs.  If unset, the script runs once and exits.                     |
| `DOMAIN_SUFFIX`          | Optional suffix (e.g. `.home.arpa`) used to filter host names.  Only host names ending in this suffix will be synced. |
| `DEBUG`                  | If set (e.g. `1`), prints verbose logs, including the discovered host → IP mapping and actions taken.    |
| `DRY_RUN`                | If set (e.g. `1`), prints the planned host → IP mapping and exits without applying changes to UniFi.     |

### Example (Docker Compose)

Below is a minimal `docker-compose.yml` example showing how to run the sync
container once every hour.  It assumes Traefik is reachable at
`http://traefik:8080` from the sync container and that SSH key based access is
used for the UniFi OS device.  Adjust volumes and secrets as necessary.

```yaml
version: '3.8'

services:
  traefik-unifi-sync:
    build: .
    image: yourrepo/traefik-unifi-sync:latest
    environment:
      - TRAEFIK_API_URL=http://traefik:8080/api
      - UNIFI_SSH_HOST=192.168.1.1
      - UNIFI_SSH_USER=root
      - UNIFI_SSH_PRIVATE_KEY=/run/secrets/unifi_key
      - SYNC_INTERVAL=3600
    secrets:
      - unifi_key
    depends_on:
      - traefik

secrets:
  unifi_key:
    file: ./unifi_key.pem
```

### Example (Docker Swarm)

For Docker Swarm users, you can deploy the sync container as a stack and
use Docker secrets for sensitive values such as your SSH private key.  First
create a secret on your Swarm manager node:

```sh
docker secret create unifi_ssh_key ./unifi_key.pem
```

Then deploy a stack using a file like the following.  A copy of this
configuration is included as `docker-stack.yml` in this repository.  Be sure
to replace `yourrepo/traefik-unifi-sync:latest` with the image you built and
pushed to a registry (e.g. ghcr.io/myuser/traefik-unifi-sync:latest).

```yaml
version: '3.9'

services:
  traefik-unifi-sync:
    image: yourrepo/traefik-unifi-sync:latest
    environment:
      - TRAEFIK_API_URL=http://traefik:8080/api
      - UNIFI_SSH_HOST=192.168.1.1
      - UNIFI_SSH_USER=root
      - UNIFI_SSH_PRIVATE_KEY=/run/secrets/unifi_ssh_key
      - SYNC_INTERVAL=3600
    secrets:
      - unifi_ssh_key
    deploy:
      replicas: 1
      restart_policy:
        condition: any

secrets:
  unifi_ssh_key:
    external: true
```

Deploy the stack with:

```sh
docker stack deploy -c docker-stack.yml traefik-unifi-sync
```

Swarm will mount the `unifi_ssh_key` secret as a file at
`/run/secrets/unifi_ssh_key` inside the container.  The script reads the
private key from that path to authenticate to your UniFi device.  For
additional sensitive values such as Traefik API credentials you can either
set them as environment variables on the service or modify the script to
read `_FILE`‑suffixed environment variables pointing to secret files.

### Dry-run preview

If you want to see which DNS host records would be created without actually
modifying your UniFi device, set `DRY_RUN=1` when running the container.  You
can also set `DEBUG=1` to print the detailed host→IP mapping.  For example:

```bash
docker run --rm \
  -e TRAEFIK_API_URL=http://traefik:8080/api \
  -e DRY_RUN=1 \
  -e DEBUG=1 \
    ghcr.io/your-account/traefik-unifi-sync:latest
```

## Caveats

* **UniFi Network Application**:  This script targets UniFi OS gateways.  If
  you run the UniFi Network Application on a generic Linux server (e.g. as a
  container on Docker), `ubios‑udapi‑client` will not be available and the
  services API may differ.  You will need to adapt the update logic accordingly.
* **Wildcards and regex rules**:  The script only handles explicit host names
  defined in `Host()` or `HostSNI()` matchers.  Routers using `HostRegexp` or
  other complex rules are ignored.
* **Duplicated entries**:  Existing host records on the UniFi device are
  preserved and updated only when a matching host name is found.  The script
  does not remove records when a router is deleted.
* **API authentication**:  If your Traefik API is protected by middleware
  (recommended), set `TRAEFIK_USERNAME` and `TRAEFIK_PASSWORD` accordingly.

## License

This project is released under the MIT License.  See `LICENSE` for details.
