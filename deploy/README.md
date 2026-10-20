# Ubuntu HTTP Deployment

Run these steps directly on the approved Ubuntu host, `10.176.2.139`, using
company-approved manual file transfer. Do not use workstation SSH/SCP/SFTP.
The agent does not access the host or connect to a database.

## Deployment Contract

| Component | Address |
| --- | --- |
| Client endpoint | `http://10.176.2.139:39064/mcp` |
| Nginx listener | `10.176.2.139:39064` |
| MCP systemd service | `127.0.0.1:39065` |
| Existing PostgreSQL | Existing host configuration; no engine installation or migrations |

The operator selected systemd + Nginx, plain HTTP, and no authentication.
Anyone in the allowed client ranges can invoke every MCP tool. Scripts and
results travel unencrypted. Network allowlisting and Host/Origin checks do not
provide user identity, authorization, or protection against an allowed malicious
client. Obtain company-policy approval before exposing the listener. Do not
publish or forward this port to the internet.

These ports are proposals, not verified free ports. They avoid the documented
web application ports. Keep the existing web deployment, Nginx sites, database,
and firewall policy intact. Review available CPU/memory and set appropriate
systemd resource limits before exposure so MCP workloads cannot exhaust this
shared host. No Docker installation is needed.

## Prerequisites And Build

Use Ubuntu 22.04/24.04 with systemd, an approved Rust toolchain >= 1.88, and an
existing host-managed Nginx whose `http` block includes `sites-enabled/*`.
If Nginx is absent, arrange its installation with the host administrator;
review package-default listeners before starting it on a shared host.
Do not replace a container-managed proxy or a running web service.

Upload this project's source, `Cargo.toml`, `Cargo.lock`, `vendor/`, and
`deploy/` through the approved transfer process. Exclude workstation `target/`,
`.git/`, `.scratch/`, reference artifacts, and any real environment files.
Run from the uploaded project root:

```sh
uname -m
rustc --version
cargo --version
sudo ss -ltnp | grep -E ':(39064|39065)\b' || true
sudo nginx -t
```

Both proposed ports must be unused on first installation. On an update, verify
that any listeners belong to this service. If changing ports, update the unit,
proxy upstream/listener, Host/Origin maps, client examples, and smoke URLs.
Inspect existing Nginx includes locally without sharing secrets from its config.

Install only the build prerequisites if missing, under host policy:

```sh
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev ca-certificates
cargo build --locked --release --no-default-features --features database,mcp,http
```

The Linux binary is `target/release/script-audit-mcp`; a Windows `.exe` cannot
be used. Build as an ordinary user. If package or crate downloads are blocked,
use the approved company mirror/proxy; keep TLS verification enabled. Never
enable `legacy-sqlite`. This build uses database client libraries, not an engine.

The operator must verify the existing catalog/schema and a SELECT-only login
off-machine before release. Do not run migrations or database tests on the
Windows workstation. HTTP transport does not waive the production approvals
and runtime/hardware gates documented in the root README.

## First Installation

For an upgrade, use the update procedure below instead; do not overwrite an
existing environment file with the example.

```sh
getent passwd script-audit || sudo useradd --system --user-group --home-dir /opt/script-audit-mcp --no-create-home --shell /usr/sbin/nologin script-audit
sudo install -d -o root -g root -m 0755 /opt/script-audit-mcp/bin
sudo install -d -o root -g script-audit -m 0750 /opt/script-audit-mcp/etc
sudo install -o root -g root -m 0755 target/release/script-audit-mcp /opt/script-audit-mcp/bin/script-audit-mcp
sudo install -o root -g script-audit -m 0640 deploy/script-audit-mcp.env.example /opt/script-audit-mcp/etc/script-audit-mcp.env
sudoedit /opt/script-audit-mcp/etc/script-audit-mcp.env
```

Enter the actual database credentials only in that protected server file.
It is systemd `EnvironmentFile` syntax, not a shell script: no `export`, command
substitutions, or shell escaping. Surround a password with single quotes if it
contains spaces or `#`; if it contains a single quote, use systemd's double-quote
escaping rules. Do not print the file or include it in uploads/logs.

The example connects to PostgreSQL on `127.0.0.1` with explicit
`sslmode=disable`, only for an existing same-host configuration that permits it.
Do not weaken PostgreSQL's policy to fit the example. If TLS is required, use a
certificate-matching database hostname, `sslmode=verify-full`, and the optional
`PGSSLROOTCERT` PEM path. The service account must be able to read that CA file
under `/opt/script-audit-mcp/etc/`; `ProtectHome=true` prevents using a home path.
The existing PostgreSQL server must accept the selected loopback/TLS connection
and login; creating or changing database roles is a separate operator task.

Install and start only the private MCP service:

```sh
sudo install -o root -g root -m 0644 deploy/script-audit-mcp.service /etc/systemd/system/script-audit-mcp.service
sudo systemd-analyze verify /etc/systemd/system/script-audit-mcp.service
sudo systemctl daemon-reload
sudo systemctl enable --now script-audit-mcp
sudo systemctl status script-audit-mcp --no-pager
sudo journalctl -u script-audit-mcp -n 50 --no-pager
sudo ss -ltnp | grep ':39065\b'
```

Require a listener on `127.0.0.1:39065`, never `0.0.0.0` or `[::]`. Startup
reads a catalog snapshot; connection/schema failures prevent the listener.
Review logs locally and redact connection details before sharing them.

## Nginx And Network Access

Install the template as a new site; do not overwrite any existing site:

```sh
sudo test ! -e /etc/nginx/sites-available/script-audit-mcp && sudo test ! -L /etc/nginx/sites-available/script-audit-mcp && \
  sudo install -o root -g root -m 0644 deploy/nginx.conf /etc/nginx/sites-available/script-audit-mcp && \
  sudoedit /etc/nginx/sites-available/script-audit-mcp
```

If the guarded install fails, stop before `sudoedit`. Inspect the existing path
and confirm ownership; use the update procedure only for this MCP deployment.

Add approved client IPs or LAN/VPN CIDRs as `allow ...;` entries immediately
before `deny all;`. Obtain the ranges from the network administrator; the
server's IP does not establish its subnet or VPN client ranges. The template
initially permits only host-local smoke checks. Do not add `allow all;`, broad
private-address ranges, or forwarded-header-based trust. This site is a direct
LAN entry point, not an upstream-proxy configuration. Check for global Nginx
`real_ip`/`satisfy` overrides that could change address filtering.

The `map` blocks must stay in the Nginx `http` context. The exact allowed Host
is `10.176.2.139:39064`. A missing Origin is allowed for desktop/CLI clients;
the sole allowed nonempty Origin is `http://10.176.2.139:39064`. Other Origins,
including `null`, receive 403. No wildcard CORS headers are supplied. If a
client sends an unexpected Origin, inspect it and approve that exact origin
before changing the map; never accept arbitrary origins.

```sh
sudo ln -s /etc/nginx/sites-available/script-audit-mcp /etc/nginx/sites-enabled/script-audit-mcp
sudo nginx -t
sudo systemctl reload nginx
sudo ss -ltnp | grep -E ':(39064|39065)\b'
```

Run reload only after `nginx -t` succeeds. Have the network administrator allow
TCP 39064 only from those same approved sources in existing host/upstream
firewall policy. Never expose 39065, enable a firewall blindly, or flush rules.
No client authentication headers or tokens are needed.

## Operator Verification

Run on Ubuntu after installation, then repeat the protocol checks from an
allowed workstation using its HTTP client. These are real catalog operations
and are intentionally not run by the agent. A browser navigation or HTTP 405
alone does not prove MCP works.

Initialize a session through Nginx:

```sh
MCP_URL='http://10.176.2.139:39064/mcp'
SMOKE_DIR=$(mktemp -d)
curl --noproxy '*' --fail-with-body --max-time 20 -sS -D "$SMOKE_DIR/headers" -o "$SMOKE_DIR/initialize" "$MCP_URL" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"operator-smoke","version":"1"}}}'
cat "$SMOKE_DIR/initialize"
SESSION_ID=$(awk 'tolower($1)=="mcp-session-id:" {gsub("\r", "", $2); print $2}' "$SMOKE_DIR/headers")
test -n "$SESSION_ID"
```

Require HTTP 200, an initialization `result` with server capabilities, and a
nonempty session ID. The body may be SSE (`data:` records). Stop on errors.
Use the negotiated protocol version from the response if it differs below.
Complete initialization and list tools in that same session:

```sh
curl --noproxy '*' --fail-with-body --max-time 20 -sS "$MCP_URL" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: $SESSION_ID" -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
curl --noproxy '*' --fail-with-body --max-time 20 -sS "$MCP_URL" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: $SESSION_ID" -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

Require notification acceptance and a successful tools result. With each target
client, run one approved read-only catalog lookup and compare it with known
catalog content. Do not use synthetic tests as production catalog approval.

Check the proxy rejection paths; each command must print `403`:

```sh
curl --noproxy '*' --max-time 10 -sS -o /dev/null -w '%{http_code}\n' "$MCP_URL" -H 'Origin: http://untrusted.invalid'
curl --noproxy '*' --max-time 10 -sS -o /dev/null -w '%{http_code}\n' "$MCP_URL" -H 'Host: untrusted.invalid'
```

From a reachable but non-allowlisted test workstation, `/mcp` must receive 403
(or be blocked by the network firewall). From any remote workstation, 39065
must be unreachable. Check the existing web application still works. Restarts
discard in-memory MCP sessions; clients must initialize again after HTTP 404.

## Client Configuration

Use the full `/mcp` URL. Merge entries into existing configuration; do not
replace other servers. No database credentials belong on client machines.
If the company HTTP proxy intercepts private addresses, configure an approved
proxy bypass for this host in the client launch environment.

### VS Code Copilot

Add to workspace `.vscode/mcp.json` or the user MCP configuration:

```json
{
  "servers": {
    "script-audit-mcp": {
      "type": "http",
      "url": "http://10.176.2.139:39064/mcp"
    }
  }
}
```

Use `MCP: List Servers` to start it, review the server trust prompt, and verify
tool discovery. Company-managed VS Code policy may restrict remote MCP servers.

### OpenCode

Merge into `opencode.json`; disable OAuth discovery for this unauthenticated
endpoint:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "script-audit-mcp": {
      "type": "remote",
      "url": "http://10.176.2.139:39064/mcp",
      "enabled": true,
      "oauth": false
    }
  }
}
```

### Claude Code

Register in the user scope (or use project scope under your team's policy):

```sh
claude mcp add --transport http --scope user script-audit-mcp http://10.176.2.139:39064/mcp
claude mcp get script-audit-mcp
```

Open `/mcp` in Claude Code and verify connection and tool discovery. If an entry
with this name already exists, inspect it before replacing it.

## Updates And Rollback

Before each update, retain a root-only, dated backup outside the repository of
the current binary, installed unit, environment file, and Nginx site. Retain
existing permissions. Record which backup belongs to the last verified release.
Build the new binary without touching the running executable, then stage it:

```sh
sudo install -o root -g root -m 0755 target/release/script-audit-mcp /opt/script-audit-mcp/bin/script-audit-mcp.next
sudo mv /opt/script-audit-mcp/bin/script-audit-mcp.next /opt/script-audit-mcp/bin/script-audit-mcp
sudo systemctl restart script-audit-mcp
```

Repeat the protocol, allowlist, and existing-web checks. If updating the unit,
run `systemd-analyze verify` and `systemctl daemon-reload` before restart. If
updating Nginx, retain the local allowlist and run `nginx -t` before reload.

On failure, stop this MCP service, restore the backed-up binary/configuration,
verify the unit and Nginx syntax, run daemon-reload if necessary, and start the
service. Reload Nginx only after its validation succeeds. Reinitialize clients
and repeat smoke checks. No database rollback or migration is part of this
release. To withdraw a first deployment, disable only this MCP service and
remove only its `sites-enabled` symlink, then validate/reload Nginx; retain its
files and logs for investigation.

## Additional MCP Servers

Each native server gets its own service account, systemd unit, protected
environment, and unused loopback port. Use a separate Nginx listener or explicit
route for each server, with its own access policy. Reusing this template requires
unique `map` variable names. Never run every MCP service as root or share
database credentials by default. Add systemd resource limits when sizing the
host; a restart of one MCP service does not restart the others.

## References And Pending Gates

- [MCP transport and security](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
- [Nginx streaming proxy directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [Nginx source-address access rules](https://nginx.org/en/docs/http/ngx_http_access_module.html)
- [VS Code MCP configuration](https://code.visualstudio.com/docs/copilot/customization/mcp-servers)
- [OpenCode MCP servers](https://opencode.ai/docs/mcp-servers)
- [Claude Code MCP servers](https://code.claude.com/docs/en/mcp)
- [systemd environment-file syntax](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#EnvironmentFile=)

Local static checks do not prove Linux/Nginx syntax, available ports, database
connectivity, company-policy approval, firewall enforcement, or client runtime
compatibility. Those gates remain operator-run on the approved host/network.
