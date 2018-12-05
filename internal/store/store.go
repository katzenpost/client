// Package store implements an encrypted key, value container for storing cbor
// serialized objects
package store

import (
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/noise"
	"github.com/ugorji/go/codec"
	"math"
	"os"
)

var (
	cborHandle *codec.CborHandle
)

// NoiseRW implements an encrypted file
type NoiseRW struct {
	k   *ecdh.PrivateKey
	f   *os.File
	buf []byte
	p   int
}

// Create initializes a NoiseRW instance
func (n *NoiseRW) Create(f *os.File) error {
	// initialize cryptostate and decrypt file into buf
	cs := n.newCryptoState(true)
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() > 0 {
		ct := make([]byte, fi.Size())
		if _, err := f.Read(ct); err != nil {
			return err
		}
		pt, _, _, err := cs.ReadMessage(nil, ct)
		if err != nil {
			return err
		}
		n.buf = pt
	} else {
		n.buf = make([]byte, 0)
	}
	n.p = 0
	return err
}

// Read returns the decrypted bytes of a NoiseRW instance
func (n *NoiseRW) Read(p []byte) (int, error) {
	i := copy(p, n.buf[n.p:])
	n.p += i
	return i, nil
}

// Write writes to a NoiseRW encrypted file
func (n *NoiseRW) Write(p []byte) (int, error) {
	if len(n.buf[n.p:]) < len(p) {
		tmp := make([]byte, n.p+len(p))
		copy(tmp, n.buf[:n.p])
		n.buf = tmp
	}
	i := copy(n.buf[n.p:], p)
	n.p += i
	return i, nil
}

// Close encrypts the buffered NoiseRW contents and writes to disk
func (n *NoiseRW) Close() {
	n.f.Seek(0, 0)
	n.p = 0
	cs := n.newCryptoState(false)
	ct, _, _, err := cs.WriteMessage(nil, n.buf)
	if err != nil {
		panic(err)
	}
	_, err = n.f.Write(ct)
	if err != nil {
		panic(err)
	}
	n.f.Close()
}

// Destroy attempts to destroy key material and ciphertext on disk
func (n *NoiseRW) Destroy() {
	for i := 0; i < 7; i++ {
		// overwrite key memory
		buf := make([]byte, 32) // XXX: const!
		rand.Reader.Read(buf)
		n.k.FromBytes(buf)
		// overwrite buf memory
		rand.Reader.Read(n.buf)
		// overwrite file on disk ?
		n.f.Seek(0, 0)
		fi, err := n.f.Stat()
		if err != nil {
			continue
		}
		cs := n.newCryptoState(false)
		ct, _, _, err := cs.WriteMessage(nil, make([]byte, fi.Size()))
		n.f.Write(ct)
	}

	n.buf = nil
	n.f.Close()
	os.Remove(n.f.Name())
}

// NewNoiseRW creates a new NoiseRW with filename and key
func NewNoiseRW(f *os.File, key *ecdh.PrivateKey) (*NoiseRW, error) {
	_, err := f.Stat()
	if err != nil {
		return nil, err
	}
	n := new(NoiseRW)
	n.f = f
	n.k = key
	if err := n.Create(f); err != nil {
		return nil, err
	}
	return n, nil
}

// borrowed from yawning's db.go
func (n *NoiseRW) newCryptoState(forDecrypt bool) *noise.HandshakeState {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	cfg := noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeN,
		Initiator:   !forDecrypt,
		MaxMsgLen:   math.MaxInt32,
	}
	if forDecrypt {
		cfg.StaticKeypair = noise.DHKey{
			Private: n.k.Bytes(),
			Public:  n.k.PublicKey().Bytes(),
		}
	} else {
		cfg.PeerStatic = n.k.PublicKey().Bytes()
	}

	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		panic("newCryptoState: initialization failed: " + err.Error())
	}
	return hs
}
