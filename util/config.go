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
	"fmt"

	"github.com/katzenpost/client/vault"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/pelletier/go-toml"
)

// TomlConfig the mix client configuration.
// NOTE: This struct is used for unmarshaling our client toml configuration
type TomlConfig struct {
	Accounts         []Account
	ProviderPinnings []ProviderPining
	SMTPNetwork      string
	SMTPAddress      string
}

// Account is used to represent a mixnet client identity
type Account struct {
	Name     string
	Provider string
}

// ProviderPining is used pin provider wire protocol certificate
type ProviderPining struct {
	Name            string
	CertificateFile string
}

// LoadConfigTree returns a (*toml.Tree) given a filepath to a toml configuration file
func LoadConfigTree(configFilePath string) (*toml.Tree, error) {
	tree, err := toml.LoadFile(configFilePath)
	if err != nil {
		return nil, err
	}
	return tree, nil
}

func formKeyFileName(keysDir, prefix, name, provider, keyType string) string {
	return fmt.Sprintf("%s/%s_%s@%s.%s.pem", keysDir, prefix, name, provider, keyType)
}

func writeNewKeypair(keysDir, prefix, name, provider, passphrase string) error {
	privateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return err
	}
	keyFileName := formKeyFileName(keysDir, prefix, name, provider, "private")
	fmt.Println("keyfilename", keyFileName)
	v := vault.Vault{
		Passphrase: passphrase,
		Path:       keyFileName,
	}
	err = v.Seal(privateKey.Bytes())
	if err != nil {
		return err
	}
	keyFileName = formKeyFileName(keysDir, prefix, name, provider, "public")
	v = vault.Vault{
		Passphrase: passphrase,
		Path:       keyFileName,
	}
	err = v.Seal(privateKey.PublicKey().Bytes())
	if err != nil {
		return err
	}
	return nil
}

// GenerateKeys creates the key files necessary to use the client
func GenerateKeys(configFilePath, keysDir, passphrase string) error {
	tree, err := LoadConfigTree(configFilePath)
	if err != nil {
		return err
	}
	accounts := tree.Get("Account")

	fmt.Println("accounts", accounts)
	//fmt.Println("tree", tree)
	// for i := 0; i < len(int(configTree.Get("Accounts"))); i++ {
	// 	fmt.Println("i", i)
	// 	// wire protocol keys
	// 	err = writeNewKeypair(keysDir, "wire", config.Accounts[i].Name, config.Accounts[i].Provider, passphrase)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	// end to end messaging keys
	// 	err = writeNewKeypair(keysDir, "e2e", config.Accounts[i].Name, config.Accounts[i].Provider, passphrase)
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	return nil
}
