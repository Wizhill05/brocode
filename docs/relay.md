# tailscale-relay egress (isolated userspace relay)

Isolated mode `tailscale-relay` sends browser traffic through an explicit
loopback HTTP proxy hosted by a **separate userspace `tailscaled`** that you
enroll independently. It never touches host routing, the host `tailscaled`
socket/state, or system proxy settings. Host traffic keeps its own IP;
only the browser proxy route uses the exit node.

## When to use it

- The host cannot or must not change `tailscale0` / policy routing, but the
  browser still needs an explicit exit-node route.
- You want per-process isolation stronger than a shared host exit node:
  `brocode doctor` proves proxy IP == relay upstream IP and != host IP.

Existing `tailscale` (bind-to-source + table 52) and `warp` modes are
unchanged.

## Layout (private, no host reuse)

| Item | Value |
|---|---|
| Relay state dir | `<repo>/var/tailscaled-relay` (or explicit absolute `BROCODE_STATE_DIR` equivalent) |
| Relay socket | `<state>/tailscaled.sock` (never `/var/run/tailscale/...`) |
| Relay state file | `<state>/tailscaled.state` |
| Relay outbound proxy | `127.0.0.1:8080` (`--outbound-http-proxy-listen`) |
| Relay TUN | `userspace-networking` (no kernel TUN, no host routes) |
| Browser egress | `127.0.0.1:1089` (`--mode tailscale-relay`) |

Templates: `deploy/brocode-tailscaled-relay.service`,
`deploy/brocode-egress-relay.service`. They install nothing by themselves.

## Setup (operator enrollment required)

Fresh enrollment is mandatory: the relay is a new Tailscale node with its own
identity. Reusing the host node's login is not sufficient.

1. Copy the relay unit to `~/.config/systemd/user/` (or run the same
   `tailscaled` flags manually) and start it:
   `systemctl --user start brocode-tailscaled-relay`.
2. Enroll the relay node in your tailnet (interactive login or your own
   provisioned auth flow — no auth keys are stored in this repo):
   `tailscale --socket <relay.sock> up --exit-node=<exit-node-selector>`
   then `tailscale --socket <relay.sock> set --exit-node=<exit-node-selector>`.
   The enrollment selector accepts a Tailscale IP or MagicDNS/host name.
   For `doctor` (`--relay-exit-node`), prefer the StableNodeID from the
   socket-scoped status: names/IPs only match when they belong to the peer
   with that same StableNodeID. Substitute your own values; nothing here is
   a real credential or node ID.
3. Confirm socket-scoped health (never the bare host `tailscale status`):
   `tailscale --socket <relay.sock> status --json` must show
   `BackendState: Running` and an online `ExitNodeStatus` with a nonempty
   `ID` (StableNodeID). A name/IP expectation only matches the peer whose
   `ID` equals that `ExitNodeStatus.ID` and whose `ExitNode` is true;
   different-ID or contradictory flags fail closed.
4. Start the egress proxy with the matching expectation:
   `python -m brocode.infra.egress --mode tailscale-relay --relay-host 127.0.0.1 --relay-port 8080 --relay-socket <relay.sock> --relay-exit-node <exit-node-identity> --port 1089`.
5. Configure the app: `BROCODE_EGRESS_MODE=tailscale-relay`,
   `BROCODE_PROXY_URL=http://127.0.0.1:1089`.
6. Run `brocode doctor` (read-only). It checks: explicit mode, owned proxy
   listener, isolated `tailscaled` process owning the exact socket with
   `--tun=userspace-networking`, explicit private `--state`/`--statedir`
   under `<state>/tailscaled-relay`, and the configured loopback proxy.
   Process proof requires: exe resolves to the installed `tailscaled`,
   expected UID, socket stat is a UID-owned UNIX socket, owner-only relay
   dirs, and the same PID owns the exact UNIX socket and the loopback TCP
   listener (incomplete inspection fails closed). Socket/state paths must be
   canonical (no traversal, `//` alias, or symlinks) under the private relay
   dir and never under host state; flags accept both `--key=value` and
   `--key value` with duplicates rejected. Running + online socket-scoped
   exit identity match and proxy IP == relay upstream IP != host IP are then
   verified. Any mismatch fails closed; there is no fallback route.

To stop: `systemctl --user stop brocode-egress-relay brocode-tailscaled-relay`.
No host routes, host `tailscaled`, or system proxy are modified at any point.

## Failure modes

- Relay daemon missing/wrong socket, wrong `--tun`, or proxy-listen mismatch
  → `relay tailscaled` check fails; browser never starts.
- Exit node offline, missing, or identity mismatch → `relay exit node` /
  `relay exit identity` checks fail.
- Upstream rejects tunnel → browser requests get HTTP 502; no silent
  fallback to direct, host exit node, or WARP.
- Live activation always requires your independent enrollment; checked-in code
  is a deployable path only, not an active route.
