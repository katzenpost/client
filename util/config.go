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
	"os"

	"github.com/katzenpost/client/vault"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/pelletier/go-toml"
)

// loadConfigTree returns a (*toml.Tree) given a filepath to a toml configuration file
func loadConfigTree(configFilePath string) (*toml.Tree, error) {
	tree, err := toml.LoadFile(configFilePath)
	if err != nil {
		return nil, err
	}
	return tree, nil
}

func formKeyFileName(keysDir, prefix, name, provider, keyType string) string {
	return fmt.Sprintf("%s/%s_%s@%s.%s.pem", keysDir, prefix, name, provider, keyType)
}

func getUserKeys(configFile, passphrase, keysDir string) (map[string]*ecdh.PrivateKey, error) {
	keysMap := make(map[string]*ecdh.PrivateKey)
	tree, err := loadConfigTree(configFile)
	if err != nil {
		return nil, err
	}
	accountsTree := tree.Get("Account").([]*toml.Tree)
	for i := 0; i < len(accountsTree); i++ {
		name := accountsTree[i].Get("name").(string)
		provider := accountsTree[i].Get("provider").(string)
		email := fmt.Sprintf("%s@%s", name, provider)
		keyfile := formKeyFileName(keysDir, "e2e", name, provider, "private")
		v := vault.Vault{
			Type:       "private",
			Email:      email,
			Passphrase: passphrase,
			Path:       keyfile,
		}
		privateKeyBytes, err := v.Open()
		if err != nil {
			return nil, err
		}
		privateKey := new(ecdh.PrivateKey)
		privateKey.FromBytes(privateKeyBytes)
		keysMap[email] = privateKey
	}
	return keysMap, nil
}

func writeNewKeypair(keysDir, prefix, name, provider, passphrase string) error {
	log.Notice("Writing new keypair")
	privateKeyFile := formKeyFileName(keysDir, prefix, name, provider, "private")
	publicKeyFile := formKeyFileName(keysDir, prefix, name, provider, "public")
	_, err1 := os.Stat(privateKeyFile)
	_, err2 := os.Stat(publicKeyFile)
	if os.IsNotExist(err1) && os.IsNotExist(err2) {
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
		v = vault.Vault{
			Type:       "public",
			Email:      email,
			Passphrase: passphrase,
			Path:       publicKeyFile,
		}
		log.Notice("performing key stretching computation")
		err = v.Seal(privateKey.PublicKey().Bytes())
		if err != nil {
			return err
		}
		return nil
	} else {
		return errors.New("key file already exists. aborting")
	}
}

// GenerateKeys creates the key files necessary to use the client
func GenerateKeys(configFilePath, keysDir, passphrase string) error {
	tree, err := loadConfigTree(configFilePath)
	if err != nil {
		return err
	}
	accountsTree := tree.Get("Account").([]*toml.Tree)
	for i := 0; i < len(accountsTree); i++ {
		name := accountsTree[i].Get("name")
		provider := accountsTree[i].Get("provider")
		if name != nil && provider != nil {
			// wire protocol keys
			err = writeNewKeypair(keysDir, "wire", name.(string), provider.(string), passphrase)
			if err != nil {
				return err
			}
			// end to end messaging keys
			err = writeNewKeypair(keysDir, "e2e", name.(string), provider.(string), passphrase)
			if err != nil {
				return err
			}
		} else {
			return errors.New("received nil Account name or provider")
		}
	}
	return nil
}
