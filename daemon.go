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
	"github.com/katzenpost/client/common"
)

// ClientDaemon handles the startup and shutdown of all client services
type ClientDaemon struct {
	config *common.Config
}

// Start starts the client services
func (c *ClientDaemon) Start() {
	log.Debug("Client startup.")
	// XXX fix me
}

// Stop stops the client services
func (c *ClientDaemon) Stop() {
	// XXX fix me
	log.Debug("Client shutdown.")
}

// NewClientDaemon creates a new ClientDaemon given a Config
func NewClientDaemon(config *common.Config) *ClientDaemon {
	c := ClientDaemon{
		config: config,
	}
	return &c
}
