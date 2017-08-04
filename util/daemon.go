// daemon.go - management of client services
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
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/wire/server"
	"github.com/op/go-logging"
)

const (
	DefaultSMTPNetwork = "tcp"
	DefaultSMTPAddress = "127.0.0.1:2525"
)

var log = logging.MustGetLogger("mixclient")

// ClientDaemon handles the startup and shutdown of all client services
type ClientDaemon struct {
	config     *Config
	passphrase string
	keysDir    string
	userPKI    UserPKI
	mixPKI     pki.Mix
}

// NewClientDaemon creates a new ClientDaemon given a Config
func NewClientDaemon(config *Config, passphrase string, keysDirPath string, userPKI UserPKI, mixPKI pki.Mix) (*ClientDaemon, error) {
	d := ClientDaemon{
		config:     config,
		passphrase: passphrase,
		keysDir:    keysDirPath,
		userPKI:    userPKI,
		mixPKI:     mixPKI,
	}
	return &d, nil
}

// Start starts the client services:
// SMTP submission proxy
// TODO:
// Add POP3 retreival proxy
func (c *ClientDaemon) Start() error {
	log.Debug("Client startup.")

	var smtpServer *server.Server
	providerAuthenticator, err := newProviderAuthenticator(c.config)
	if err != nil {
		return err
	}

	smtpProxy := NewSubmitProxy(c.config, providerAuthenticator, rand.Reader, c.userPKI, c.mixPKI)

	if len(c.config.SMTPProxy.Network) == 0 {
		log.Debug("using default smtp proxy addr")
		smtpServer = server.New(DefaultSMTPNetwork, DefaultSMTPAddress, smtpProxy.handleSMTPSubmission, nil)
	} else {
		log.Debug("not using default smtp proxy addr")
		smtpServer = server.New(c.config.SMTPProxy.Network, c.config.SMTPProxy.Address, smtpProxy.handleSMTPSubmission, nil)
	}
	err = smtpServer.Start()
	return err
}

// Stop stops the client services
func (c *ClientDaemon) Stop() {
	log.Debug("Client shutdown.")
}
