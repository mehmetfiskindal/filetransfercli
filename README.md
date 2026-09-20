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
- Optional phone UI: `filetransfer bridge` serves a small web app that drives
  transfers from a browser on the same LAN (see [Phone UI](#phone-ui))

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

## Phone UI

`filetransfer bridge` turns one machine into the sender you can drive from a
phone. The phone only sends commands and renders progress; file bytes never
touch it. They travel machine-to-machine over the same TLS engine the CLI uses,
so a phone on flaky WiFi cannot slow the transfer down.

```
 phone browser  ──WebSocket JSON──▶  filetransfer bridge  ──TLS chunks──▶  filetransfer receive
  (control only)                       (machine A)                          (machine B)
```

Start the receiver on the destination machine:

```sh
filetransfer receive -addr :8443 -secret "shared-secret" -out ~/Downloads
```

Start the bridge on the machine holding the files:

```sh
filetransfer bridge -addr :8080 -root ~/Documents \
  -www filetransfer/.gea/build/web/site \
  -peer 192.168.1.20:8443 -secret "shared-secret"
```

Then open `http://<machine-A-ip>:8080` on the phone, enter the shared secret
under **Setup**, pick files, and hit **Send**.

Flags: `-root` is the only directory the bridge will read from (paths that
escape it are refused), `-www` is the built app to serve, `-peer` pre-fills a
suggested destination, and `-secret` is the secret the app must present before
the bridge will list or send anything.

### Building the app

The UI is a GeaStack app in [`filetransfer/`](filetransfer). It needs Node 20.19+:

```sh
cd filetransfer
npm install
npm run check   # tsc --noEmit
npm run build   # gea build --target web -> .gea/build/web/site
npm run dev     # live preview on localhost, no bridge needed to see the UI
```

`gea build --target android` is **not** available: the installed `gea` CLI
(0.1.78) only drives the `web`, `esp32-*`, and `rp2350-*` targets and reports
that an Android build must come from a separate Android target project. The
manifest still declares `android: true` to record the intent. Until that
project exists, the phone path is the web build loaded in the phone's browser,
which is a normal page on the LAN and needs no install.

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
