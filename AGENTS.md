# AGENTS.md

Peer-to-peer file transfer CLI between two machines (macOS ↔ Linux) over local WiFi/LAN.

## Decisions (already agreed — do not revisit without asking)
- **Language:** Go, single static binary, no runtime dependencies. Prefer stdlib (`net`, `crypto/tls`, `net/http`) over third-party deps; add a dependency only with justification.
- **Scope:** LAN only. No NAT traversal, relay, or rendezvous server.
- **MVP features:** send a single file, recursive directory transfer, progress + resume, auth/encryption.

## Architecture
- Two roles: **sender** (push) and **receiver** (listen), run as subcommands of one binary (e.g. `filetransfer send` / `filetransfer receive`).
- Encrypt all traffic with TLS; require a shared secret/password or pre-shared key for auth (do not send plaintext on shared networks).
- Resume must be based on file offset/length checksum, not filename alone (handles interrupted transfers and directory recursion).
- Keep cross-platform: avoid OS-specific syscalls; paths via `filepath`; support both `darwin` and `linux`.

## Build & cross-compile
```sh
go build ./...                      # local build
GOOS=darwin GOARCH=arm64 go build -o dist/filetransfer-macos-arm64 .   # Apple Silicon
GOOS=darwin GOARCH=amd64 go build -o dist/filetransfer-macos-amd64 .   # Intel Mac
GOOS=linux  GOARCH=amd64 go build -o dist/filetransfer-linux-amd64 .   # Linux x86_64
```
- `dist/` holds release binaries; keep it gitignored.

## Verification
```sh
go test ./...
go vet ./...
gofmt -l .
```
