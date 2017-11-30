// config.go - mixnet client configuration
// Copyright (C) 2017  David Anthony Stainton, Yawning Angel
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

// Package provides mixnet client configuration utilities
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/crypto/vault"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/utils"
	"github.com/pelletier/go-toml"
)

const (
	defaultLogLevel = "NOTICE"
)

var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Account is used to deserialize the account sections
// of the configuration file.
type Account struct {
	// Name is the first part of an e-mail address
	// before the @-sign.
	Name string
	// Provider is the second part of an e-mail address
	// after the @-sign.
	Provider string
}

// Proxy is used to deserialize the proxy
// configuration sections of the configuration
// for the SMTP and POP3 proxies.
type Proxy struct {
	// Network is the transport type e.g. "tcp"
	Network string
	// Address is the transport address
	Address string
}

// Logging is the Katzenpost client logging configuration.
type Logging struct {
	// Disable disables logging entirely.
	Disable bool

	// File specifies the log file, if omitted stdout will be used.
	File string

	// Level specifies the log level.
	Level string
}

func (lCfg *Logging) validate() error {
	lvl := strings.ToUpper(lCfg.Level)
	switch lvl {
	case "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG":
	case "":
		lCfg.Level = defaultLogLevel
	default:
		return fmt.Errorf("config: Logging: Level '%v' is invalid", lCfg.Level)
	}
	lCfg.Level = lvl // Force uppercase.
	return nil
}

// Nonvoting is a non-voting directory authority.
type Nonvoting struct {
	// Address is the authority's IP/port combination.
	Address string

	// PublicKey is the authority's public key in Base64 or Base16 format.
	PublicKey string
}

func (nCfg Nonvoting) validate() error {
	if err := utils.EnsureAddrIPPort(nCfg.Address); err != nil {
		return fmt.Errorf("config: PKI/Nonvoting: Address is invalid: %v", err)
	}

	var pubKey eddsa.PublicKey
	if err := pubKey.FromString(nCfg.PublicKey); err != nil {
		return fmt.Errorf("config: PKI/Nonvoting: Invalid PublicKey: %v", err)
	}

	return nil
}

// PKI is the Katzenpost directory authority configuration.
type PKI struct {
	// Nonvoting is a non-voting directory authority.
	Nonvoting *Nonvoting
}

func (pCfg *PKI) validate() error {
	nrCfg := 0
	if pCfg.Nonvoting != nil {
		if err := pCfg.Nonvoting.validate(); err != nil {
			return err
		}
		nrCfg++
	}
	if nrCfg != 1 {
		return fmt.Errorf("config: Only one authority backend should be configured, got: %v", nrCfg)
	}
	return nil
}

// Config is used to deserialize the configuration file
type Config struct {
	// DataDir is the absolute path to the client's state files.
	DataDir string
	// Logging controls logging parameters
	Logging *Logging
	// Account is the list of accounts represented by this client configuration
	Account []Account
	// PKI configures the PKI
	PKI *PKI
	// SMTPProxy is the transport configuration of the SMTP submission proxy
	SMTPProxy *Proxy
	// POP3Proxy is the transport configuration of the POP3 receive proxy
	POP3Proxy *Proxy
}

// AccountsMap map of email to user private key
// for each account that is used
type AccountsMap map[string]*ecdh.PrivateKey

// GetIdentityKey returns a private key corresponding to the
// given lower cased identity/email
func (a *AccountsMap) GetIdentityKey(email string) (*ecdh.PrivateKey, error) {
	key, ok := (*a)[strings.ToLower(email)]
	if ok {
		return key, nil
	}
	return nil, errors.New("identity key not found")
}

// CreateKeyFileName composes a filename given several arguments
// arguments:
// * keysDir - a filepath to the directory containing the key files.
//   must not end in a forward slash /.
// * keyType - indicates weather the key is used for end to end crypto or
//   wire protocol link layer crypto and should be set to one of the following:
//   * constants.EndToEndKeyType
//   * constants.LinkLayerKeyType
// * name - name of the account, first section of an e-mail address before the @-sign.
// * provider - the Provider name, the second section of an e-mail address after the @-sign.
// * keyStatus - indicates weather the key is public or private and should be set to
//   on of the following constants:
//   * constants.KeyStatusPrivate
//   * constants.KeyStatusPublic
func CreateKeyFileName(keysDir, keyType, name, provider, keyStatus string) string {
	pemFile := fmt.Sprintf("%s_%s@%s.%s.pem", keyType, name, provider, keyStatus)
	return filepath.Join(keysDir, pemFile)
}

// GetAccountKey decrypts and returns a private key material or an error
// arguments:
// * keyType - indicates weather the key is used for end to end crypto or
//   wire protocol link layer crypto and should be set to one of the following:
//   * constants.EndToEndKeyType
//   * constants.LinkLayerKeyType
// * account - an instance of the Account struct
//   must not end in a forward slash /.
// * passphrase - a secret passphrase which is used to decrypt keys on disk
func (c *Config) GetAccountKey(keyType string, account Account, passphrase string) (*ecdh.PrivateKey, error) {
	privateKeyFile := CreateKeyFileName(c.DataDir, keyType, account.Name, account.Provider, constants.KeyStatusPrivate)
	email := fmt.Sprintf("%s@%s", account.Name, account.Provider)
	v := vault.Vault{
		Type:       constants.KeyStatusPrivate,
		Email:      email,
		Passphrase: passphrase,
		Path:       privateKeyFile,
	}
	plaintext, err := v.Open()
	if err != nil {
		return nil, err
	}
	key := ecdh.PrivateKey{}
	key.FromBytes(plaintext)
	return &key, nil
}

// AccountsMap returns an Accounts struct which contains
// a map of email to private key for each account
// arguments:
// * keyType - indicates weather the key is used for end to end crypto or
//   wire protocol link layer crypto and should be set to one of the following:
//   * constants.EndToEndKeyType
//   * constants.LinkLayerKeyType
// * keysDir - a filepath to the directory containing the key files.
//   must not end in a forward slash /.
// * passphrase - a secret passphrase which is used to decrypt keys on disk
func (c *Config) AccountsMap(keyType, passphrase string) (*AccountsMap, error) {
	accounts := make(AccountsMap)
	for _, account := range c.Account {
		email := fmt.Sprintf("%s@%s", account.Name, account.Provider)
		privateKey, err := c.GetAccountKey(keyType, account, passphrase)
		if err != nil {
			return nil, err
		}
		accounts[strings.ToLower(email)] = privateKey
	}
	return &accounts, nil
}

// AccountIdentities returns a list of e-mail addresses or
// account identities which the user has configured
func (c *Config) AccountIdentities() []string {
	accounts := []string{}
	for _, account := range c.Account {
		email := fmt.Sprintf("%s@%s", account.Name, account.Provider)
		accounts = append(accounts, email)
	}
	return accounts
}

// writeKey generates and encrypts a key to disk
func writeKey(keysDir, prefix, name, provider, passphrase string) error {
	privateKeyFile := CreateKeyFileName(keysDir, prefix, name, provider, constants.KeyStatusPrivate)
	_, err := os.Stat(privateKeyFile)
	if os.IsNotExist(err) {
		privateKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			return err
		}
		email := fmt.Sprintf("%s@%s", name, provider)
		v := vault.Vault{
			Type:       constants.KeyStatusPrivate,
			Email:      email,
			Passphrase: passphrase,
			Path:       privateKeyFile,
		}
		err = v.Seal(privateKey.Bytes())
		if err != nil {
			return err
		}
		return nil
	} else {
		return errors.New("key file already exists. aborting")
	}
}

func SplitEmail(email string) (string, string, error) {
	fields := strings.Split(email, "@")
	if len(fields) != 2 {
		return "", "", errors.New("splitEmail: email format invalid")
	}
	return fields[0], fields[1], nil
}

// GenerateKeys creates the key files necessary to use the client
func (c *Config) GenerateKeys(passphrase string) error {
	var err error
	for i := 0; i < len(c.Account); i++ {
		name := c.Account[i].Name
		provider := c.Account[i].Provider
		if name != "" && provider != "" {
			err = writeKey(c.DataDir, constants.LinkLayerKeyType, name, provider, passphrase)
			if err != nil {
				return err
			}
			err = writeKey(c.DataDir, constants.EndToEndKeyType, name, provider, passphrase)
			if err != nil {
				return err
			}
		} else {
			return errors.New("received nil Account name or provider")
		}
	}
	return nil
}

// FixupAndValidate applies defaults to config entries and validates the
// supplied configuration.
func (cfg *Config) FixupAndValidate() error {
	if cfg.DataDir == "" {
		return errors.New("config: No DataDir was present")
	}
	if cfg.Account == nil {
		return errors.New("config: No Account block was present")
	}
	if cfg.Logging == nil {
		cfg.Logging = &defaultLogging
	}
	if cfg.PKI == nil {
		return errors.New("config: No PKI block was present")
	}
	if err := cfg.PKI.validate(); err != nil {
		return err
	}
	if err := cfg.Logging.validate(); err != nil {
		return err
	}
	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte) (*Config, error) {
	cfg := new(Config)
	if err := toml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadFile loads, parses and validates the provided file and returns the
// Config.
func LoadFile(f string) (*Config, error) {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b)
}
