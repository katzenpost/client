// daemon.go - mixnet client
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

// Package main provides a mixnet client daemon
package main

import (
	"crypto/rand"
	//"encoding/base64"
	"io/ioutil"
	"net"

	"github.com/katzenpost/core/wire/common"
	"github.com/katzenpost/core/wire/server"
	"github.com/pelletier/go-toml"
)

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

// Client is a mix client configuration struct
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

func (t *TomlConfig) Config() (*Config, error) {
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

// ClientDaemon handles the startup and shutdown of all client services
type ClientDaemon struct {
	config  *Config
	session *common.Session
	conn    net.Conn
}

// NewClientDaemon creates a new ClientDaemon given a Config
func NewClientDaemon(config *Config) *ClientDaemon {
	sessionConfig := common.Config{
		Initiator:  true,
		Identifier: config.Identifier,
		Random:     rand.Reader,
		//LongtermEd25519PublicKey:  config.PublicEd25519Key,
		//LongtermEd25519PrivateKey: config.PrivateEd25519Key,
	}
	c := ClientDaemon{
		config:  config,
		session: common.New(&sessionConfig, nil),
	}
	return &c
}

// Start starts the client services
func (c *ClientDaemon) Start() error {
	log.Debug("Client startup.")

	log.Noticef("Starting SMTP submission proxy on %s:%s", c.config.SMTPProxyNetwork, c.config.SMTPProxyAddress)

	smtpServer := server.New(c.config.SMTPProxyNetwork, c.config.SMTPProxyAddress, smtpServerHandler, nil) // XXX todo: use logging
	err := smtpServer.Start()
	if err != nil {
		panic(err)
	}

	// err = c.Dial(c.config.ProviderNetwork, c.config.ProviderAddress)
	// if err != nil {
	// 	log.Debugf("dial failed: %s", err)
	// 	return err
	// }
	return nil
}

// Stop stops the client services
func (c *ClientDaemon) Stop() {
	// XXX fix me
	log.Debug("Client shutdown.")
}

func (c *ClientDaemon) Dial(network, address string) error {
	var err error
	c.conn, err = net.Dial(network, address)
	if err != nil {
		log.Notice("failed to dial provider")
		return err
	}
	return c.session.Initiate(c.conn)
}

func (c *ClientDaemon) Read() (*common.Command, error) {
	cmd, err := c.session.Receive()
	if err != nil {
		log.Debugf("session read error: %s", err)
		return nil, err
	}
	return &cmd, nil
}

func (c *ClientDaemon) Write(cmd *common.Command) error {
	err := c.session.Send(*cmd)
	if err != nil {
		log.Debugf("session write error: %s", err)
		return err
	}
	return nil
}
