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

type Config struct {
	Identifier             []byte
	ProviderAuthPublicKey  []byte
	ProviderAuthPrivateKey []byte
	ClientPublicKey        []byte
	ClientPrivateKey       []byte
	ProviderNetwork        string
	ProviderAddress        string
	SMTPProxyNetwork       string
	SMTPProxyAddress       string
	ShouldAutoGenKeys      bool
}

// TomlConfig is used for unmarshaling our client toml configuration
type TomlConfig struct {
	Client Client
}

// Client is a mix client configuration struct.
// This struct is referenced by TomlConfig struct
type Client struct {
	Username                   string
	Provider                   string
	ProviderAuthPublicKeyFile  string
	ProviderAuthPrivateKeyFile string
	ClientPublicKeyFile        string
	ClientPrivateKeyFile       string
	ProviderNetwork            string
	ProviderAddress            string
	SMTPProxyNetwork           string
	SMTPProxyAddress           string
}

func (t *TomlConfig) Config(passphrase string) (*Config, error) {

	providerAuthPubKey, err := ioutil.ReadFile(t.Client.ProviderAuthPublicKeyFile)
	if err != nil {
		log.Critical("Failed to read key file")
		os.Exit(1)
	}
	providerAuthPrivKey, err := ioutil.ReadFile(t.Client.ProviderAuthPrivateKeyFile)
	if err != nil {
		log.Critical("Failed to read key file")
		os.Exit(1)
	}
	clientPubKey, err := ioutil.ReadFile(t.Client.ClientPublicKeyFile)
	if err != nil {
		log.Critical("Failed to read key file")
		os.Exit(1)
	}
	clientPrivKey, err := ioutil.ReadFile(t.Client.ClientPrivateKeyFile)
	if err != nil {
		log.Critical("Failed to read key file")
		os.Exit(1)
	}

	// publicKeyBase64, err := ioutil.ReadFile(t.Client.PublicKeyFile)
	// if err != nil {
	// 	return nil, err
	// }
	// privateKeyBase64, err := ioutil.ReadFile(t.Client.PrivateKeyFile)
	// if err != nil {
	// 	return nil, err
	// }
	// publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyBase64))
	// if err != nil {
	// 	log.Debugf("failed to decode base64 public key: %s", err)
	// 	return nil, err
	// }
	// privateKey, err := base64.StdEncoding.DecodeString(string(privateKeyBase64))
	// if err != nil {
	// 	log.Debugf("failed to decode base64 private key: %s", err)
	// 	return nil, err
	// }
	c := Config{
		Identifier: []byte(t.Client.Username + t.Client.Provider),
		// PublicEd25519Key:  publicKey,
		// PrivateEd25519Key: privateKey,
		ProviderNetwork:  t.Client.ProviderNetwork,
		ProviderAddress:  t.Client.ProviderAddress,
		SMTPProxyNetwork: t.Client.SMTPProxyNetwork,
		SMTPProxyAddress: t.Client.SMTPProxyAddress,
	}
	return &c, nil
}

// LoadConfig returns a *Config given a filepath to a configuration file
func LoadConfig(configFilePath string) (*TomlConfig, error) {
	config := TomlConfig{}
	lines, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}
	if err := toml.Unmarshal([]byte(lines), &config); err != nil {
		return nil, err
	}
	return &config, nil
}
