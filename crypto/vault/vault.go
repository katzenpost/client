// vault.go - cryptographic vault for mixnet client key material
// Copyright (C) 2017  David Anthony Stainton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// crypto vault
package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"

	"github.com/magical/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// argon2SaltSize is the salt size in bytes for use with argon2
	argon2SaltSize = 8

	// passphraseMinSize is the minimum allowed passphrase size in bytes
	passphraseMinSize = 12

	// secretboxNonceSize is the nonce size in bytes for NaCl SecretBox
	secretboxNonceSize = 24
)

// Vault is used to Encrypt sensitive data to disk.
// Uses argon2 for keystretching and NaCl SecretBox
// for encryption.
type Vault struct {
	Type       string
	Passphrase string
	Path       string
	Email      string
}

// New creates a new Vault
func New(vaultType, passphrase, path, email string) (*Vault, error) {
	if len(passphrase) < passphraseMinSize {
		return nil, errors.New("passphrase too short")
	}
	v := Vault{
		Type:       vaultType,
		Email:      email,
		Passphrase: passphrase,
		Path:       path,
	}
	return &v, nil
}

// stretch performs argon2 key stretching on the given passphrase
func (v *Vault) stretch(passphrase string) ([]byte, error) {
	salt := passphrase[0:argon2SaltSize]
	pass := passphrase[argon2SaltSize:]

	// length in bytes of output key
	keyLen := 32

	// argon2 cost parameters

	// parallelism
	par := 2

	// mem is the amount of memory to use in kibibytes.
	// (mem must be at least 8*p, and will be rounded to a multiple of 4*p)
	mem := int64(1 << 16)

	// number of iterations
	n := 32

	out, err := argon2.Key([]byte(pass), []byte(salt), n, par, mem, keyLen)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Open returns decrypted data from the vault
func (v *Vault) Open() ([]byte, error) {
	pemPayload, err := ioutil.ReadFile(v.Path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemPayload)
	if block == nil {
		return nil, errors.New("failed to decode pem file")
	}

	var nonce [24]byte
	copy(nonce[:], block.Bytes[0:24])

	var key [32]byte
	stretchedKey, err := v.stretch(v.Passphrase)
	if err != nil {
		return nil, err
	}
	copy(key[:], stretchedKey)

	ciphertext := make([]byte, len(block.Bytes[24:]))
	copy(ciphertext, block.Bytes[24:])

	out := []byte{}
	plaintext, isAuthed := secretbox.Open(out, ciphertext, &nonce, &key)
	if !isAuthed {
		return nil, errors.New("NaCl secretBox MAC failed")
	}

	return plaintext, nil
}

// Seal encrypts given plaintext and writes
// it into the vault, saving it to a file on disk
func (v *Vault) Seal(plaintext []byte) error {
	key, err := v.stretch(v.Passphrase)
	if err != nil {
		return err
	}
	sealKey := [32]byte{}
	copy(sealKey[:], key)

	nonce := [secretboxNonceSize]byte{}
	_, err = rand.Reader.Read(nonce[:])
	if err != nil {
		return err
	}

	out := []byte{}
	ciphertext := secretbox.Seal(out, plaintext, &nonce, &sealKey)

	fileMode := os.FileMode(0600)
	payload := make([]byte, len(ciphertext)+secretboxNonceSize)
	copy(payload, nonce[:])
	copy(payload[secretboxNonceSize:], ciphertext)

	headers := map[string]string{
		"email": v.Email,
	}
	block := pem.Block{
		Type:    v.Type,
		Headers: headers,
		Bytes:   payload,
	}
	buf := new(bytes.Buffer)
	pem.Encode(buf, &block)

	err = ioutil.WriteFile(v.Path, buf.Bytes(), fileMode)
	if err != nil {
		return err
	}
	return nil
}
