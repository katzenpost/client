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
	creds *wire.PeerCredentials
}

// IsPeerValid authenticates the remote peer's credentials, returning true
// iff the peer is valid.
func (a *peerAuthenticator) IsPeerValid(peer *wire.PeerCredentials) bool {
	if subtle.ConstantTimeCompare(a.creds.AdditionalData, peer.AdditionalData) != 1 {
		return false
	}
	if subtle.ConstantTimeCompare(a.creds.PublicKey.Bytes(), peer.PublicKey.Bytes()) != 1 {
		return false
	}

	return true
}

// ClientDaemon handles the startup and shutdown of all client services
type ClientDaemon struct {
	config     *toml.Tree
	passphrase string
	keysDir    string
}

// NewClientDaemon creates a new ClientDaemon given a Config
func NewClientDaemon(configFile string, passphrase string, keysDirPath string) (*ClientDaemon, error) {
	configTree, err := LoadConfigTree(configFile)
	if err != nil {
		return nil, err
	}
	d := ClientDaemon{
		config:     configTree,
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
	submissionProxy := MailSubmissionProxy{}
	if c.config.Get("SMTPProxy.Network") == nil || c.config.Get("SMTPProxy.Address") == nil {
		smtpServer = server.New(DefaultSMTPNetwork,
			DefaultSMTPAddress,
			submissionProxy.handleSMTPSubmission,
			nil)
	} else {
		smtpServer = server.New(c.config.Get("SMTPProxy.Network").(string),
			c.config.Get("SMTPProxy.Address").(string),
			submissionProxy.handleSMTPSubmission,
			nil)
	}
	err := smtpServer.Start()
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
