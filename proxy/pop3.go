// pop3.go - POP3 + mixnet proxy server.
// Copyright (C) 2017  David Stainton.
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

// Package proxy provides mixnet client proxies
package proxy

import (
	"net"
	"strings"

	"github.com/katzenpost/client/pop3"
	"github.com/katzenpost/client/storage"
)

// Pop3BackendSession is our boltdb backed implementation
// of our pop3 BackendSession interface
type Pop3BackendSession struct {
	store       *storage.Store
	accountName string
}

// Messages returns a list of messages stored in our
// bolt database
func (s Pop3BackendSession) Messages() ([][]byte, error) {
	messages, err := s.store.Messages(s.accountName)
	return messages, err
}

// DeleteMessages deletes a list of messages
func (s Pop3BackendSession) DeleteMessages(items []int) error {
	return s.store.DeleteMessages(s.accountName, items)
}

// Close closes the session in this case
// closing our database handle
func (s Pop3BackendSession) Close() {
	return
}

// Pop3Backend implements our pop3 Backend interface
type Pop3Backend struct {
	store *storage.Store
}

// NewPop3Backend creates a new Pop3Backend given the db file path
func NewPop3Backend(store *storage.Store) Pop3Backend {
	p := Pop3Backend{
		store: store,
	}
	return p
}

// NewSession returns a BackendSession implementation or an error given
// the user name and password
func (b Pop3Backend) NewSession(user, pass []byte) (pop3.BackendSession, error) {
	accountName := strings.ToLower(string(user))
	return Pop3BackendSession{
		store:       b.store,
		accountName: accountName,
	}, nil
}

// Pop3Service is a pop3 service which is backed by
// a local boltdb
type Pop3Service struct {
	store *storage.Store
}

// NewPop3Service creates a new Pop3Service
// with the given boltdb filename
func NewPop3Service(store *storage.Store) *Pop3Service {
	s := Pop3Service{
		store: store,
	}
	return &s
}

// HandleConnection is a blocking function that uses the given
// connection to handle a pop3 session
func (s *Pop3Service) HandleConnection(conn net.Conn) error {
	defer conn.Close()
	backend := NewPop3Backend(s.store)
	pop3Session := pop3.NewSession(conn, backend)
	pop3Session.Serve()
	return nil
}
