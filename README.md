# NextPATH (Next-generation Policy-Applied Traffic Handler) 

NextPATH is a high-performance, industrial-grade DNS filtering and dynamic traffic routing system written in **Go**. It represents a complete redesign and evolution of the original [PATH](https://github.com/QuasyStellar/PATH) project, migrating the entire processing, dynamic IP allocation, and P2P replication engine from Python to compiled Go.

NextPATH processes DNS queries for selected domains, returns temporary Fake-IP addresses from a designated subnet to clients, dynamically creates destination NAT (DNAT) rules in the Linux kernel via stateless netlink batching (`nftables`), and forwards traffic through a gateway without requiring the distribution of massive routing tables to client devices. This allows seamless access to private encrypted overlays and proxied routes while maintaining compatibility with legacy network equipment.

---

## Key Advantages

*   **Hybrid Dynamic IP Allocation:** Uses Level 1 stateless hashing combined with Level 2 IPv6/IPv4 Linear Probing and Node Striding for collision resolution, offering rapid and robust allocation without massive memory overhead.
*   **Conflict-Free Distributed Roaming:** Handles concurrent client mapping edits across multiple distributed nodes using a robust lock-free P2P sync tie-breaker, versioned conflict resolution (via Hybrid Logical Clocks - HLC), and a unified cache model to mathematically prevent split-brain issues.
*   **Multi-Core DNS Processing:** NextPATH uses `SO_REUSEPORT` to spawn multiple `kresd` worker processes per instance, scaling effortlessly across all available CPU cores.
*   **Zero-Config Certificate Pinning (Strict TLS):** Deploy P2P clusters instantly without complex PKI. NextPATH supports deterministic SHA-256 certificate fingerprint verification (`NEXTPATH_SYNC_STRICT_TLS=pinning`). It accepts single or multiple comma-separated fingerprints, enabling seamless rolling certificate updates and hybrid cluster support.
*   **Encrypted Direct TCP P2P Synchronization:** Cluster synchronization of routing tables is executed securely over an encrypted Strict TLS tunnel using direct TCP connections. Features support for real domain certificates, ServerName SNI verification, and mutual token authentication.
*   **Enterprise Observability:** Native Prometheus exporter (`/metrics` on `:9090`) tracking DNS queries, IP pool capacity, active allocations, network collisions, and P2P sync latency in real-time.
*   **Seamless DNSSEC Bypassing:** Normal web traffic is strictly cryptographically validated via DNSSEC to prevent spoofing and MitM attacks. Meanwhile, proxied domains gracefully bypass DNSSEC validation (using `policy.STUB`, stripping `RRSIG`/`NSEC`/`NSEC3` records, and clearing the `AD` flag) to allow Fake-IP routing without triggering client-side `SERVFAIL` errors.
*   **Lightning-Fast List Compilation:** Built-in Go list compiler featuring O(N) domain collapsing using string reversal and native sorting, processing millions of rules in seconds.

---

## Hybrid Dynamic IP Allocation Architecture

NextPATH implements a hybrid two-tier IP allocation model to map selected domains to the Fake-IP pool:

1. **Level 1: Stateless Direct Hashing**: When a DNS query is processed, NextPATH statelessly hashes (using FNV-1a) the real IP to a candidate Fake-IP within the dynamically calculated CIDR subnet.
2. **Level 2: Collision Resolution using IPv6/IPv4 Linear Probing**: If the candidate IP is already leased in the IPCache, NextPATH probes through alternative slots using Linear Probing combined with Node Striding to find an available Fake-IP. This prevents nodes from allocating the exact same conflicting IPs simultaneously.
3. **Unified Cache Model**: Active IP-to-domain allocations are stored in a streamlined, unified thread-safe in-memory cache, eliminating dual-locking overhead and redundant state to provide a single source of truth for routing.
4. **Versioned Conflict Resolution (Hybrid Logical Clocks)**: Tracks a monotonic version value using Hybrid Logical Clocks (HLC) for each mapping entry to act as a robust P2P tie-breaker. This safely eliminates wall-clock drift issues and mathematically prevents split-brain scenarios during distributed concurrent updates.

---

## DNS Service Architecture

NextPATH provides two independent DNS service addresses for different operational needs:

*   **NextPATH DNS (`10.77.77.77`)**: Policy-based traffic handling mode. Resolves selected domains to Fake-IP addresses for routing through the gateway, while returning real IPs for everything else. This is the default recommended choice for policy-based traffic management.
*   **Full DNS (`10.88.88.88`)**: Clean recursive mode. Returns real IPs for **all** domains but still applies filtering for ads and privacy enhancements.

---

## Deployment & Setup

NextPATH is distributed as a lightweight Docker container (`< 75MB` compressed, based on `debian:12-slim`).

### Pre-requisites
- Docker & Docker Compose
- Linux Kernel with `nftables` support

### Quick Start
1. Create a working directory and pull the configuration:
   ```bash
   mkdir -p nextpath && cd nextpath
   curl -O https://raw.githubusercontent.com/QuasyStellar/NextPATH/main/docker-compose.yml
   curl -o .env https://raw.githubusercontent.com/QuasyStellar/NextPATH/main/.env.example
   ```
2. Open the `.env` file in your preferred text editor and adjust the variables to fit your network (e.g., `UPSTREAM_DNS`, `FAKE_IP`).
3. Start the stack:
   ```bash
   docker compose up -d
   ```

### Docker Swarm Cluster Deployment
If you are running a cluster of nodes, you can deploy NextPATH globally across all swarm managers and workers using the provided stack file. Because Docker Swarm does not support `privileged: true` or traditional `network_mode: host`, the stack file natively mounts the external `host` network and explicitly defines `cap_add: [NET_ADMIN, NET_RAW]` to allow manipulation of the physical host's `nftables`. This bypasses Swarm's overlay DNS discovery, so you must explicitly define your node IPs in the `.env` file (`PEERS` variable) for cluster synchronization.

1. **Initialize Docker Swarm** (if not already initialized):
   ```bash
   docker swarm init
   ```
2. **Create Docker Secrets** for the P2P Sync TLS certificates. The stack configuration automatically mounts these as `/run/secrets/cert.pem` and `/run/secrets/key.pem`:
   ```bash
   docker secret create nextpath_cert /path/to/your/fullchain.pem
   docker secret create nextpath_key /path/to/your/privkey.pem
   ```
3. **Download the stack configuration**:
   ```bash
   curl -O https://raw.githubusercontent.com/QuasyStellar/NextPATH/main/docker-stack.yml
   curl -o .env https://raw.githubusercontent.com/QuasyStellar/NextPATH/main/.env.example
   ```
4. **Configure your environment**:
   Open the `.env` file and configure it. Specifically, you **must** set the `PEERS` variable with a comma-separated list of your Swarm node IPs, and set `NEXTPATH_SYNC_TOKEN` to a secure password.
5. **Deploy to the Swarm**:
   ```bash
   docker stack deploy -c docker-stack.yml nextpath
   ```

#### Swarm Operations & Cheat Sheet

Once your cluster is running, here are the most useful commands for managing NextPATH globally:

**Rolling Image Updates**
When a new version of `quasystellaris/nextpath:latest` is released, you can force all nodes to pull the new image and perform a rolling restart:
```bash
docker service update --image quasystellaris/nextpath:latest nextpath_nextpath
```

**Viewing Logs for a Specific Node**
By default, `docker service logs -f nextpath_nextpath` mixes logs from all servers. To isolate logs:
1. Find the specific task ID for the node you want: `docker service ps nextpath_nextpath`
2. View its specific logs: `docker service logs -f <TASK_ID>` (e.g. `docker service logs -f j5dqrjnedlj2`)

**Scaling the Cluster**
Because the stack uses `deploy: mode: global`, scaling is fully automatic. Simply add a new server to your Swarm:
```bash
# On the manager node, get the join token:
docker swarm join-token worker

# On the new server, paste the output:
docker swarm join --token <TOKEN> <MANAGER_IP>:2377
```
Docker Swarm will instantly detect the new node, deploy the NextPATH container to it, and securely inject the TLS certificates. Just remember to add the new IP to the `PEERS` list in your `.env` and run `docker stack deploy` to notify the existing nodes.

---

## Domain List Management & Compilation

NextPATH supports two compilation modes: **Centralized Compilation via GitHub Actions** and **Local Compilation on your Server**.

### Centralized Compilation
Centralized compilation is highly convenient for distributed systems. It compiles your lists once in the cloud and publishes them to a release branch. All nodes in your mesh then download the exact same compiled lists, ensuring absolute consistency and saving CPU/RAM resources across your servers.

To use centralized compilation:
1. Configure your lists using GitHub Repository Secrets.
2. The daily scheduled GitHub Actions workflow `compile.yml` will automatically compile them and publish a compressed bundle to the `lists-release` branch.
3. Your servers will automatically download and update lists from this branch using HTTP ETag caching.

#### Supported GitHub Repository Secrets

* **GitHub Secret (URL):** Define a list of URLs to remote lists (one URL per line).
* **GitHub Secret (Manual):** Define raw domains, IPs, or subnets directly (one entry per line).

| List Type | GitHub Secret (URL) | GitHub Secret (Manual) | Description |
|---|---|---|---|
| **Route Domains** | `URLS_INCLUDE_HOSTS` | `MANUAL_INCLUDE_HOSTS` | Domains to route through the proxy. |
| **Bypass Domains** | `URLS_EXCLUDE_HOSTS` | `MANUAL_EXCLUDE_HOSTS` | Domains to bypass the proxy. |
| **Route IPs** | `URLS_INCLUDE_IPS` | `MANUAL_INCLUDE_IPS` | IP ranges to route through the proxy. |
| **Bypass IPs** | `URLS_EXCLUDE_IPS` | `MANUAL_EXCLUDE_IPS` | IP ranges to bypass the proxy. |
| **Block IPs** | `URLS_DENY_IPS` | `MANUAL_DENY_IPS` | IP ranges to block completely. |
| **Adblock Domains** | `URLS_ADBLOCK_HOSTS` | `MANUAL_ADBLOCK_HOSTS` | Adblocking and tracking domains. |
| **Adblock Whitelist** | `URLS_EXCLUDE_ADBLOCK_HOSTS` | `MANUAL_EXCLUDE_ADBLOCK_HOSTS` | Domains to whitelist from adblocking. |
| **Remove Domains** | `URLS_REMOVE_HOSTS` | `MANUAL_REMOVE_HOSTS` | Domains to strip from the compiled lists. |
| **Custom RPZ** | `URLS_RPZ` | `MANUAL_RPZ` | Custom RPZ zone entries to import. |
| **Custom RPZ 2** | `URLS_RPZ2` | `MANUAL_RPZ2` | Custom RPZ zone 2 entries to import. |

---

### Local Compilation
If you prefer to run compilation locally on your server instead of using GitHub Actions:
1. Set `COMPILE_LOCAL=true` in your `.env`.
2. Edit the corresponding text files directly inside the `lists/` directory.
3. The engine will compile these files locally upon startup and reload them periodically based on `COMPILE_INTERVAL`.

#### Supported Local Configuration Files

* **Local File (URL):** Put URLs to remote lists (one URL per line).
* **Local File (Manual):** Put raw domains, IPs, or subnets directly (one entry per line).

| List Type | Local File (URL) | Local File (Manual) | Description |
|---|---|---|---|
| **Route Domains** | `lists/sources/include-hosts.txt` | `lists/manual/include-hosts.txt` | Domains to route through the proxy. |
| **Bypass Domains** | `lists/sources/exclude-hosts.txt` | `lists/manual/exclude-hosts.txt` | Domains to bypass the proxy. |
| **Route IPs** | `lists/sources/include-ips.txt` | `lists/manual/include-ips.txt` | IP ranges to route through the proxy. |
| **Bypass IPs** | `lists/sources/exclude-ips.txt` | `lists/manual/exclude-ips.txt` | IP ranges to bypass the proxy. |
| **Block IPs** | `lists/sources/deny-ips.txt` | `lists/manual/deny-ips.txt` | IP ranges to block completely. |
| **Adblock Domains** | `lists/sources/include-adblock-hosts.txt` | `lists/manual/include-adblock-hosts.txt` | Adblocking and tracking domains. |
| **Adblock Whitelist** | `lists/sources/exclude-adblock-hosts.txt` | `lists/manual/exclude-adblock-hosts.txt` | Domains to whitelist from adblocking. |
| **Remove Domains** | `lists/sources/remove-hosts.txt` | `lists/manual/remove-hosts.txt` | Domains to strip from the compiled lists. |
| **Custom RPZ** | `lists/sources/rpz.txt` | `lists/manual/rpz.txt` | Custom RPZ zone entries to import. |
| **Custom RPZ 2** | `lists/sources/rpz2.txt` | `lists/manual/rpz2.txt` | Custom RPZ zone 2 entries to import. |

---

## P2P Cluster Synchronization

If you deploy NextPATH across geographically distributed nodes, you can synchronize them to ensure seamless roaming and shared DNS caches for your clients.

When a client connects to **Node A** and resolves a selected domain, the node allocates a Fake-IP and adds a DNAT rule. The client's OS caches this IP. If the client then reconnects or roams to **Node B** and attempts to open the site using the cached Fake-IP, Node B will normally drop the connection because it lacks the DNAT mapping.

NextPATH solves this with built-in **Encrypted Direct TCP P2P Synchronization**:
- Set the `PEERS` variable on each node to point to the other nodes in your mesh.
- Provide TLS certificates (using real, CA-signed Let's Encrypt certificates is highly recommended for security) by mounting them into the container.
- Provide a secure cluster password via `NEXTPATH_SYNC_TOKEN`.
- Whenever any node allocates a Fake-IP, it instantly broadcasts the mapping to all connected peers over a strictly verified, encrypted TLS tunnel.
- All nodes in the cluster stay perfectly in sync. This guarantees that cached Fake-IPs remain globally valid across your entire network.
- **Wildcard Certificate Support**: Strict TLS fully supports wildcard certificates (e.g., `*.yourdomain.com`). When providing CA-signed certificates, NextPATH securely verifies the ServerName during the encrypted TLS handshake.

### Mounting External TLS Certificates

By default, the NextPATH engine automatically searches for P2P TLS certificates in `/run/secrets/cert.pem` (and `key.pem`) for Docker Swarm deployments, and then falls back to `/app/nextpath/certs/cert.pem` (and `key.pem`) for standard Docker Compose deployments. You can override these paths using the `NEXTPATH_SYNC_CERT` and `NEXTPATH_SYNC_KEY` environment variables. If you are deploying via Docker Swarm, the default `docker-stack.yml` natively maps your Docker Secrets to `/run/secrets/cert.pem` and `/run/secrets/key.pem` for secure injection, meaning zero configuration is required.

If you are using external CA-signed certificates or DoH certificates in a standard Docker Compose setup, mount your directory into the container using your `docker-compose.yml` volumes section:

```yaml
volumes:
  # Map your host's certificates directory to the container
  - ./certs:/app/nextpath/certs:ro
```

### TLS Certificate Pinning

NextPATH supports a highly secure **Zero-Config Certificate Pinning** mode for cluster synchronization, designed specifically for self-signed certificates.

When you set `NEXTPATH_SYNC_STRICT_TLS=pinning`, NextPATH skips standard Certificate Authority (CA) checks and instead verifies that the remote peer's certificate SHA-256 fingerprint exactly matches your local certificate.

Since Docker Swarm/Compose deployments typically mount the same `./certs` directory to all nodes, this provides out-of-the-box MITM protection without complex PKI infrastructure.

If your nodes use different self-signed certificates, you can manually specify a comma-separated list of expected hashes:
`NEXTPATH_SYNC_CERT_FINGERPRINT=hash1,hash2,hash3...`

### Certificate Generation Quick Start
If you do not have CA-signed certificates, you can quickly generate self-signed certificates:

1. Run the generator directly:
   ```bash
   bash <(curl -Ls https://raw.githubusercontent.com/QuasyStellar/NextPATH/main/scripts/generate_self_signed_certs.sh)
   ```
   This will generate `cert.pem` and `key.pem` inside the `./certs` folder.

2. Mount the generated `./certs` directory to your container in `docker-compose.yml`:
   ```yaml
   volumes:
     - ./certs:/app/nextpath/certs:ro
   ```

3. Configure your `.env` file depending on your cluster setup:

   **Scenario A: Same certificates on all nodes (Recommended)**
   If you copy the exact same `./certs` folder to every node in your cluster, use Certificate Pinning. NextPATH will automatically calculate the fingerprint of your local certificate and use it to verify incoming connections.
   ```env
   NEXTPATH_SYNC_STRICT_TLS=pinning
   NEXTPATH_SYNC_CERT_FINGERPRINT=
   ```

   **Scenario B: Different certificates on each node**
   If you generated unique self-signed certificates for every node, you must still use `pinning`, but you need to explicitly list the expected fingerprints of all your peers:
   ```env
   NEXTPATH_SYNC_STRICT_TLS=pinning
   NEXTPATH_SYNC_CERT_FINGERPRINT=peer1_hash,peer2_hash
   ```

   **Scenario C: Insecure Mode (Not Recommended)**
   If you want to quickly test the connection and don't care about Man-In-The-Middle (MITM) attacks, you can completely disable TLS verification. This will work regardless of whether the certificates are the same or different.
   ```env
   NEXTPATH_SYNC_STRICT_TLS=false
   ```

---

## Configuration Reference

All parameters are configured via environment variables in the `.env` file. (Refer to the `.env.example` file for details).

### Core Settings & Routing
| Variable | Default | Description |
|----------|---------|-------------|
| `UPSTREAM_DNS` | `1` | Upstream DNS selection (1–7) ([see sets below](#upstream_dns-upstream-sets)) or custom comma-separated IPs. |
| `CUSTOM_DNS_ROUTES` | `ru...` | Routes queries for specific top-level domains to specific servers. |
| `OPENNIC_IPS` | `94...` | Custom IP list for OpenNIC TLD resolution. |
| `ENABLE_IPV6` | `y` | Enable dual-stack IPv6 parsing, allocation, and routing. |
| `IPV6_PROXY_ONLY` | `y` | Restrict IPv6 resolution exclusively to proxied domains. |
| `PUBLIC_DNS` | `n` | Open DNS port 53 to public external network interfaces. |
| `EXTERNAL_IP` | - | Public IP address to bind when `PUBLIC_DNS=y`. |

### DoH Endpoint
| Variable | Default | Description |
|----------|---------|-------------|
| `DOH_ENABLE` | `n` | Enable DNS-over-HTTPS (DoH) endpoint. *(Note: container falls back to `n` if certs are missing)* |
| `DOH_PORT` | `443` | HTTPS port for the DoH endpoint. |
| `DOH_CERT` | `/app/nextpath/certs/cert.pem` | Path to the DoH TLS certificate. Defaults to `/run/secrets/cert.pem` in Docker Swarm mode. |
| `DOH_KEY` | `/app/nextpath/certs/key.pem` | Path to the DoH TLS private key. Defaults to `/run/secrets/key.pem` in Docker Swarm mode. |

### Engine & Compiler
| Variable | Default | Description |
|----------|---------|-------------|
| `LIST_SOURCE` | - | URL to a remote pre-compiled `.tar.gz` list archive. If set, skips local compilation. |
| `LIST_POLL_INTERVAL` | `2h` | How often to check for updates when using a remote `LIST_SOURCE`. |
| `COMPILE_LOCAL` | `n` | Enable local compilation of routing lists on engine startup. |
| `COMPILE_INTERVAL` | `24h` | How often to re-run local compilation when `COMPILE_LOCAL=y`. |
| `COMPILE_ONLY` | `n` | If `y`, compile/download lists once and exit immediately (useful for CI). |
| `ROUTE_ALL` | `n` | If `y`, compiles all processed domains as specific proxied routes. |
| `BLOCK_ADS` | `y` | Enable ad-filtering RPZ zone. Accepts `y`/`n`/`true`/`false`. |
| `FILTER_CASINO` | `y` | Strip gambling domains from compiled lists. |
| `DNS_RATE_LIMIT` | `300` | Max UDP/TCP DNS queries per second per source IP. |
| `AGGREGATE_COUNT` | `500` | Target limit for the number of IP prefixes in nftables sets. |

### Fake-IP Pool
| Variable | Default | Description |
|----------|---------|-------------|
| `FAKE_IP` | `198.18` | IPv4 prefix for the Fake-IP pool. |
| `POOL_SIZE_V4` | `15` | CIDR mask for the IPv4 Fake-IP range (e.g. `15` = `/15` = ~131k IPs). |
| `FAKE_IP6` | `fd00:18::` | IPv6 prefix for the Fake-IP pool. |
| `POOL_SIZE_V6` | `111` | CIDR mask for the IPv6 Fake-IP range (e.g. `111` = `/111` = ~131k IPs). |
| `MAX_FAKE_IP_TTL` | `300` | DNS response TTL (seconds) for Fake-IP answers. |

### P2P Sync Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `PEERS` | - | Comma-separated list of cluster nodes for P2P sync (e.g. `1.2.3.4,5.6.7.8`). |
| `SYNC_PORT` | `5353` | Listening port for incoming P2P sync TLS connections. |
| `NEXTPATH_SYNC_TOKEN` | - | P2P cluster authentication token. Use a strong, random 64-character string. |
| `NEXTPATH_SYNC_CERT` | `/app/nextpath/certs/cert.pem` | Path to the P2P Sync TLS certificate. Defaults to `/run/secrets/cert.pem` in Docker Swarm mode. |
| `NEXTPATH_SYNC_KEY` | `/app/nextpath/certs/key.pem` | Path to the P2P Sync TLS private key. Defaults to `/run/secrets/key.pem` in Docker Swarm mode. |
| `NEXTPATH_SYNC_STRICT_TLS` | `y` | TLS mode: `y` (standard CA checks, supports wildcards), `n` (insecure), or `pinning` (Zero-Config Certificate Pinning). |
| `NEXTPATH_SYNC_CERT_FINGERPRINT` | - | (Optional) 32-byte HEX hash of the peer's certificate. Required only if using `pinning` mode. |

### Metrics & Debug
| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_ENABLE` | `n` | Enable the Prometheus metrics exporter. |
| `METRICS_ADDR` | `127.0.0.1` | IP address to bind the metrics server. |
| `METRICS_PORT` | `9090` | Port for the Prometheus metrics exporter. |
| `DEBUG` | `n` | Enable verbose debug logs for the Go engine. Accepts `y`/`n`/`true`/`false`. |

### Internal Architecture (Advanced)
| Variable | Default | Description |
|----------|---------|-------------|
| `NEXTPATH_DNS_IP` | `10.77.77.77` | Internal IP of the NextPATH DNS gateway. |
| `GLOBAL_DNS_IP` | `10.88.88.88` | Internal IP of the Full DNS gateway. |
| `DNS_ADDR_1` | `127.0.0.1` | Loopback address for Knot Resolver instance 1 (NextPATH DNS). |
| `DNS_ADDR_2` | `127.0.0.2` | Loopback address for Knot Resolver instance 2 (Full DNS). |
| `PROXY_ADDR` | `127.0.0.3` | Loopback address for the Go DNS proxy listener. |
| `PROXY_PORT` | `53` | Port for the Go DNS proxy listener. |
| `KRESD_WORKERS` | `auto` | Number of Knot Resolver worker processes per instance. |
| `CACHE_SIZE` | `5%` | Knot Resolver cache size **per instance**. Because there are 2 instances, total RAM used is double this value (e.g., `5%` = 10% total, `256` = 512MB total). |

---

---

### UPSTREAM_DNS Upstream Sets

| `UPSTREAM_DNS` | Description | Upstream IPs |
|-----------|-------------|--------------|
| `1` | Cloudflare+Quad9 | `1.1.1.1`, `1.0.0.1`, `9.9.9.10`, `149.112.112.10` |
| `2` | Google + Cloudflare| `8.8.8.8`, `8.8.4.4`, `1.1.1.1` |
| `3` | OpenDNS | `208.67.222.222`, `208.67.220.220` |
| `4` | Quad9 (No ECS) | `9.9.9.10`, `149.112.112.10` |
| `5` | ControlD + Quad9 | `76.76.2.0`, `9.9.9.10` |
| `6` | AdGuard DNS Global | `94.140.14.140`, `94.140.14.141` |
| `7` | CleanBrowsing (Family) | `185.228.168.168`, `185.228.169.168` |

---

## Diagnostics & Troubleshooting

### View Proxied Routing Maps in nftables:
```bash
# View IPv4 proxied routing mappings
nft list map inet nextpath v4_map

# View IPv6 proxied routing mappings
nft list map inet nextpath v6_map
```

### Exporting Prometheus Metrics:
NextPATH exposes a dependency-free, built-in Prometheus metrics server. It is **disabled by default**. To enable it, set `METRICS_ENABLE=true` in your `.env` file. You can also specify the interface using `METRICS_ADDR` and `METRICS_PORT`.
Once enabled (by default on `127.0.0.1:9090`), you can scrape it using a Prometheus server, or query the metrics manually:
```bash
# Run this from the host machine to see metrics
curl http://localhost:9090/metrics
```

### View Supervisor & NextPATH Engine logs:
```bash
docker logs -f nextpath
```

### Check Worker Status:
```bash
docker exec nextpath supervisorctl status
```

### Manually Trigger List Reload/Recompilation:
If you want to force NextPATH to immediately reload remote lists or recompile local lists without restarting the entire container, restart the updater worker:
```bash
docker exec nextpath supervisorctl restart nextpath-updater
```

