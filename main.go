package main

import (
	"flag"
	"fmt"
	"os"

	"filetransfer/internal"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "send":
		sendCmd(os.Args[2:])
	case "receive":
		receiveCmd(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func sendCmd(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	to := fs.String("to", "", "receiver address (host:port)")
	secretFlag := fs.String("secret", "", "shared secret")
	fs.Usage = func() { usage() }
	fs.Parse(args)

	secret, err := resolveSecret(*secretFlag)
	if err != nil {
		fatal(err)
	}
	if *to == "" {
		fatal(fmt.Errorf("-to is required (e.g. -to 192.168.1.20:8443)"))
	}
	paths := fs.Args()
	if len(paths) == 0 {
		fatal(fmt.Errorf("no paths to send"))
	}

	if err := internal.Send(internal.SendConfig{To: *to, Secret: secret, Paths: paths}); err != nil {
		fatal(err)
	}
}

func receiveCmd(args []string) {
	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	addr := fs.String("addr", ":8443", "listen address")
	out := fs.String("out", ".", "output directory")
	secretFlag := fs.String("secret", "", "shared secret")
	fs.Usage = func() { usage() }
	fs.Parse(args)

	secret, err := resolveSecret(*secretFlag)
	if err != nil {
		fatal(err)
	}

	if err := internal.Receive(internal.ReceiveConfig{Addr: *addr, Secret: secret, OutDir: *out}); err != nil {
		fatal(err)
	}
}

func resolveSecret(flagValue string) ([]byte, error) {
	if flagValue != "" {
		return []byte(flagValue), nil
	}
	if env := os.Getenv("FILETRANSFER_SECRET"); env != "" {
		return []byte(env), nil
	}
	return nil, fmt.Errorf("no secret: pass -secret or set FILETRANSFER_SECRET")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `filetransfer — peer-to-peer file transfer over LAN

Usage:
  filetransfer receive -addr :8443 [-out DIR] -secret SECRET
  filetransfer send -to HOST:PORT -secret SECRET PATH...

The secret may be provided with -secret or the FILETRANSFER_SECRET env var.
Both sides must use the same secret.
`)
}
