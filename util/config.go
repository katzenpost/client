// config.go - mixnet client configuration
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

// Package util provides client utilities
package util

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/katzenpost/client/vault"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/pelletier/go-toml"
)

func createKeyFileName(keysDir, prefix, name, provider, keyType string) string {
	return fmt.Sprintf("%s/%s_%s@%s.%s.pem", keysDir, prefix, name, provider, keyType)
}

func writeKey(keysDir, prefix, name, provider, passphrase string) error {
	privateKeyFile := createKeyFileName(keysDir, prefix, name, provider, "private")
	_, err := os.Stat(privateKeyFile)
	if os.IsNotExist(err) {
		privateKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			return err
		}
		email := fmt.Sprintf("%s@%s", name, provider)
		v := vault.Vault{
			Type:       "private",
			Email:      email,
			Passphrase: passphrase,
			Path:       privateKeyFile,
		}
		log.Notice("performing key stretching computation")
		err = v.Seal(privateKey.Bytes())
		if err != nil {
			return err
		}
		return nil
	} else {
		return errors.New("key file already exists. aborting")
	}
}

type Account struct {
	Name     string
	Provider string
}

type ProviderPinning struct {
	PublicKeyFile string
	Name          string
}

type SMTPProxy struct {
	Address string
	Network string
}

type Config struct {
	Account         []Account
	ProviderPinning []ProviderPinning
	SMTPProxy       SMTPProxy
}

func FromFile(fileName string) (*Config, error) {
	config := Config{}
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	err = toml.Unmarshal([]byte(fileData), &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// GenerateKeys creates the key files necessary to use the client
func (c *Config) GenerateKeys(keysDir, passphrase string) error {
	var err error
	for i := 0; i < len(c.Account); i++ {
		name := c.Account[i].Name
		provider := c.Account[i].Provider
		if name != "" && provider != "" {
			// wire protocol keys
			err = writeKey(keysDir, "wire", name, provider, passphrase)
			if err != nil {
				return err
			}
			// end to end messaging keys
			err = writeKey(keysDir, "e2e", name, provider, passphrase)
			if err != nil {
				return err
			}
		} else {
			return errors.New("received nil Account name or provider")
		}
	}
	return nil
}
