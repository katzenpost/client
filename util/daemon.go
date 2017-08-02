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
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("mixclient")

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
	return nil
}

// Stop stops the client services
func (c *ClientDaemon) Stop() {
	log.Debug("Client shutdown.")
}
