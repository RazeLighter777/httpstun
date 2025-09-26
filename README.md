# httpstun

Simple experimental HTTP/WebSocket based TUN tunnel.

## Server

Run the server (defaults shown):

```
cargo run -p httpstun_server -- --port 8080 --host 127.0.0.1 --tun-interface-name tun0 --external-interface-name eth0 --config-file ./httpstun_server.toml
```

Interactively add a client (requires interactive mode):

```
add_client
Enter client name: client1
Enter client password: ********
```

## Client

The client creates a TUN interface and forwards packets over a WebSocket POST `/` to the server with headers:

* X-Httpstun-Client-Name
* X-Httpstun-Client-Password

Run (needs CAP_NET_ADMIN or root to create TUN):

```
sudo cargo run -p httpstun_client -- \
  --server-url http://127.0.0.1:8080/ \
  --client-name client1 \
  --client-password <plain-password> \
  --tun-interface-name tun0
```

Optional flags: --config-file (TOML with `[client_args]` table) and --log-level.

## Notes

* Password is sent to server for Argon2 verification against stored hash.
* Proof-of-concept: no MTU negotiation, encryption relies on HTTPS/WSS if used, no automatic route setup.
* Manually configure IP and routes on both ends' TUN devices.

## Security Warning

Not production ready: lacks replay protection, robust auth hardening, and key management.

## Capabilities Helper Script

Instead of running with `sudo`, you can grant the binaries `CAP_NET_ADMIN` so they can create TUN devices:

```
./scripts/setup_caps.sh          # build debug binaries and set caps
./scripts/setup_caps.sh --release # build release binaries and set caps
./scripts/setup_caps.sh --dry-run # show what would be done
```

Verify:

```
getcap target/debug/httpstun_client
getcap target/debug/httpstun_server
```

If capabilities fail to apply (e.g. in some container filesystems), fall back to running with sudo:

```
sudo target/debug/httpstun_client --server-url http://127.0.0.1:8080/ --client-name client1 --client-password <pw>
```