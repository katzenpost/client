// daemon.go - client management of configurations and services
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
	"crypto/subtle"
	"encoding/pem"
	"io/ioutil"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/server"
	"github.com/op/go-logging"
	"github.com/pelletier/go-toml"
)

const (
	DefaultSMTPNetwork = "tcp"
	DefaultSMTPAddress = "127.0.0.1:2525"
)

var log = logging.MustGetLogger("mixclient")

type peerAuthenticator struct {
	keysMap map[[255]byte]*ecdh.PublicKey
}

func newPeerAuthenticator(configFile, passphrase, keysDir string) (*peerAuthenticator, error) {
	tree, err := loadConfigTree(configFile)
	if err != nil {
		return nil, err
	}
	pinnings := tree.Get("ProviderPinning").([]*toml.Tree)
	keysMap := make(map[[255]byte]*ecdh.PublicKey)
	for i := 0; i < len(pinnings); i++ {
		name := pinnings[i].Get("name").([]byte)
		pemPayload, err := ioutil.ReadFile(pinnings[i].Get("certificate").(string))
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pemPayload)
		if block == nil {
			return nil, err
		}
		publicKey := new(ecdh.PublicKey)
		publicKey.FromBytes(block.Bytes)
		nameField := [255]byte{}
		copy(nameField[:], name)
		keysMap[nameField] = publicKey
	}
	authenticator := peerAuthenticator{
		keysMap: keysMap,
	}
	return &authenticator, nil
}

// IsPeerValid authenticates the remote peer's credentials, returning true
// iff the peer is valid.
func (a *peerAuthenticator) IsPeerValid(peer *wire.PeerCredentials) bool {
	nameField := [255]byte{}
	copy(nameField[:], peer.AdditionalData)
	_, ok := a.keysMap[nameField]
	if !ok {
		return false
	}
	if subtle.ConstantTimeCompare(a.keysMap[nameField].Bytes(), peer.PublicKey.Bytes()) != 1 {
		return false
	}
	return true
}

// ClientDaemon handles the startup and shutdown of all client services
type ClientDaemon struct {
	configFile string
	passphrase string
	keysDir    string
}

// NewClientDaemon creates a new ClientDaemon given a Config
func NewClientDaemon(configFile string, passphrase string, keysDirPath string) (*ClientDaemon, error) {
	d := ClientDaemon{
		configFile: configFile,
		passphrase: passphrase,
		keysDir:    keysDirPath,
	}
	return &d, nil
}

// Start starts the client services:
// 1. SMTP submission proxy
// 2. POP3 retreival proxy
func (c *ClientDaemon) Start() error {
	log.Debug("Client startup.")
	var smtpServer *server.Server

	peerAuthenticator, err := newPeerAuthenticator(c.configFile, c.passphrase, c.keysDir) // XXX
	if err != nil {
		return err
	}
	userKeysMap, err := getUserKeys(c.configFile, c.passphrase, c.keysDir) // XXX
	if err != nil {
		return err
	}
	submissionProxy := NewSubmitProxy(peerAuthenticator, rand.Reader, userKeysMap)

	config, err := loadConfigTree(c.configFile)
	if err != nil {
		return err
	}

	if config.Get("SMTPProxy.Network") == nil || config.Get("SMTPProxy.Address") == nil {
		smtpServer = server.New(DefaultSMTPNetwork,
			DefaultSMTPAddress,
			submissionProxy.handleSMTPSubmission,
			nil)
	} else {
		smtpServer = server.New(config.Get("SMTPProxy.Network").(string),
			config.Get("SMTPProxy.Address").(string),
			submissionProxy.handleSMTPSubmission,
			nil)
	}
	err = smtpServer.Start()
	if err != nil {
		panic(err)
	}

	return nil
}

// Stop stops the client services
func (c *ClientDaemon) Stop() {
	// XXX fix me
	log.Debug("Client shutdown.")
}
