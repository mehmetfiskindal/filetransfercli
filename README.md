# filetransfer

Peer-to-peer file transfer CLI for local networks. Send files and directories
between macOS and Linux machines over WiFi/LAN with TLS encryption and
resumable transfers.

## Features

- Single static binary, no runtime dependencies (stdlib only)
- Send a single file or recursive directories
- Mutual TLS authenticated by a shared secret (no plaintext on the network)
- Progress bar and transfer summary
- Resumable transfers based on chunk checksums (SHA-256), not filename alone

## Install

Prebuilt binaries are attached to releases, or build from source:

```sh
go build -o filetransfer .
```

Cross-compile for both platforms:

```sh
GOOS=darwin GOARCH=arm64 go build -o dist/filetransfer-macos-arm64 .   # Apple Silicon
GOOS=darwin GOARCH=amd64 go build -o dist/filetransfer-macos-amd64 .   # Intel Mac
GOOS=linux  GOARCH=amd64 go build -o dist/filetransfer-linux-amd64 .   # Linux x86_64
```

## Usage

Both sides must use the same secret.

Receiver (listens for a sender):

```sh
filetransfer receive -addr :8443 -secret "shared-secret" -out .
```

Sender (pushes files/directories to the receiver):

```sh
filetransfer send -to 192.168.1.20:8443 -secret "shared-secret" file.txt dir/
```

Instead of `-secret`, you can set the `FILETRANSFER_SECRET` environment
variable to avoid exposing the secret in shell history.

If a transfer is interrupted, re-running the same `send` resumes from the last
matching chunk; already-complete files are skipped.

## Security

- All traffic is encrypted with TLS; each peer verifies the other using the
  shared secret, so a wrong secret cannot complete the handshake.
- Resume offsets are validated against per-chunk SHA-256 hashes.
- LAN only: there is no NAT traversal, relay, or rendezvous server.

## Development

```sh
go test ./...
go vet ./...
gofmt -l .
```

## License

[MIT](LICENSE)
