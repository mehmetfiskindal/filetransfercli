package internal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"
)

// buildTLS derives a deterministic ECDSA key pair from the shared secret and
// returns TLS configs for the server and client roles. Both sides derive the
// same public key, so a peer is authenticated by comparing the certificate's
// public key against our own: only someone who knows the secret can complete
// the handshake.
func buildTLS(secret []byte) (*tls.Config, *tls.Config, error) {
	priv, err := deriveKey(secret)
	if err != nil {
		return nil, nil, err
	}
	cert, err := selfSignedCert(priv)
	if err != nil {
		return nil, nil, err
	}

	wantPub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	verifyPeer := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("peer presented no certificate")
		}
		peer, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		gotPub, err := x509.MarshalPKIXPublicKey(peer.PublicKey)
		if err != nil {
			return err
		}
		if !bytes.Equal(gotPub, wantPub) {
			return errors.New("peer certificate does not match shared secret")
		}
		return nil
	}

	server := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifyPeer,
		MinVersion:            tls.VersionTLS12,
	}

	client := &tls.Config{
		InsecureSkipVerify:    true, // self-signed; verified manually above
		Certificates:          []tls.Certificate{cert},
		VerifyPeerCertificate: verifyPeer,
		MinVersion:            tls.VersionTLS12,
	}

	return server, client, nil
}

func deriveKey(secret []byte) (*ecdsa.PrivateKey, error) {
	sum := sha256.Sum256(secret)
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = new(big.Int).SetBytes(sum[:])
	priv.PublicKey.X, priv.PublicKey.Y = priv.Curve.ScalarBaseMult(sum[:])
	return priv, nil
}

func selfSignedCert(priv *ecdsa.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "filetransfer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}
