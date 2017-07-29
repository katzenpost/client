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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"os"

	"github.com/magical/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	SaltSize          = 8
	PassphraseMinSize = 12
	SecretboxNoneSize = 24
)

// Vault is used to Encrypt sensitive data to disk
type Vault struct {
	Passphrase string
	Path       string
}

func (v *Vault) stretch(passphrase string) ([]byte, error) {
	salt := passphrase[0:SaltSize]
	pass := passphrase[SaltSize:]
	par := 2
	mem := int64(1 << 16)
	keyLen := 32
	n := 32
	out, err := argon2.Key([]byte(pass), []byte(salt), n, par, mem, keyLen)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (v *Vault) Open() ([]byte, error) {
	base64Payload, err := ioutil.ReadFile(v.Path)
	if err != nil {
		return nil, err
	}

	payloadCiphertext, err := base64.StdEncoding.DecodeString(string(base64Payload))
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], payloadCiphertext[0:24])

	var key [32]byte
	stretchedKey, err := v.stretch(v.Passphrase)
	if err != nil {
		return nil, err
	}
	copy(key[:], stretchedKey)

	ciphertext := make([]byte, len(payloadCiphertext[24:]))
	copy(ciphertext, payloadCiphertext[24:])

	out := []byte{}
	plaintext, isAuthed := secretbox.Open(out, ciphertext, &nonce, &key)
	if !isAuthed {
		return nil, errors.New("NaCl secretBox MAC failed")
	}

	return plaintext, nil
}

func (v *Vault) Seal(plaintext []byte) error {
	key, err := v.stretch(v.Passphrase)
	if err != nil {
		return err
	}
	sealKey := [32]byte{}
	copy(sealKey[:], key)

	nonce := [SecretboxNoneSize]byte{}
	_, err = rand.Reader.Read(nonce[:])
	if err != nil {
		return err
	}

	out := []byte{}
	ciphertext := secretbox.Seal(out, plaintext, &nonce, &sealKey)

	fileMode := os.FileMode(0600)
	payload := make([]byte, len(ciphertext)+SecretboxNoneSize)
	copy(payload, nonce[:])
	copy(payload[SecretboxNoneSize:], ciphertext)
	base64Ciphertext := base64.StdEncoding.EncodeToString([]byte(payload))

	err = ioutil.WriteFile(v.Path, []byte(base64Ciphertext), fileMode)
	if err != nil {
		return err
	}
	return nil
}
