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

// Package provides mixnet client utilities
package client

import (
	"github.com/katzenpost/core/wire/server"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("mixclient")

// ClientDaemon handles the startup and shutdown of all client services
type ClientDaemon struct {
	smtpServer *server.Server
	pop3Server *server.Server
}

// NewClientDaemon creates a new ClientDaemon
func NewClientDaemon(smtpServer, pop3Server *server.Server) (*ClientDaemon, error) {
	d := ClientDaemon{
		smtpServer: smtpServer,
		pop3Server: pop3Server,
	}
	return &d, nil
}

// Start starts the client services
// which proxy message to and from the mixnet
// via POP3 and SMTP
func (c *ClientDaemon) Start() error {
	log.Debug("Client startup.")
	log.Debug("starting smtp proxy service")
	err := c.smtpServer.Start()
	if err != nil {
		return err
	}
	log.Debug("starting pop3 proxy service")
	err = c.pop3Server.Start()
	if err != nil {
		return err
	}
	return nil
}

// Stop stops the client services
func (c *ClientDaemon) Stop() {
	log.Debug("Client shutdown.")
	c.smtpServer.Stop()
	c.pop3Server.Stop()
}
