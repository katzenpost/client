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
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/pop3"
	"github.com/katzenpost/client/storage/ingress"
)

// Pop3BackendSession is our boltdb backed implementation
// of our pop3 BackendSession interface
type Pop3BackendSession struct {
	store       *ingress.Store
	accountName string
}

// Messages returns a list of messages stored in our
// bolt database
func (s Pop3BackendSession) Messages() ([][]byte, error) {

}

// DeleteMessages deletes a list of messages
func (s Pop3BackendSession) DeleteMessages(items []int) error {
	// XXX
	return nil
}

// Close closes the session in this case
// closing our database handle
func (s Pop3BackendSession) Close() error {
	// XXX
	return nil
}

// Pop3Backend implements our pop3 Backend interface
type Pop3Backend struct {
	dbFile string
}

// NewPop3Backend creates a new Pop3Backend given the db file path
func NewPop3Backend(dbFile string) Pop3Backend {
	p := Pop3Backend{
		dbFile: dbFile,
	}
	return p
}

// createAccountBucket uses the given db handle and account name
// to create a boltdb storage bucket
func (b Pop3Backend) createAccountBucket(db *bolt.DB, account string) error {
	transaction := func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(account))
		return err
	}
	err := db.Update(transaction)
	return err
}

// CreateAccountBuckets is used to create a set of storage account buckets
// that will store received messages
func (b Pop3Backend) CreateAccountBuckets(accounts []string) error {
	db, err := bolt.Open(b.dbFile, 0600, &bolt.Options{Timeout: constants.DatabaseConnectTimeout})
	if err != nil {
		return err
	}
	for _, account := range accounts {
		err := b.createAccountBucket(db, strings.ToLower(account))
		if err != nil {
			return err
		}
	}
	return db.Close()
}

// NewSession returns a BackendSession implementation or an error given
// the user name and password
func (b Pop3Backend) NewSession(user, pass []byte) (pop3.BackendSession, error) {
	accountName := strings.ToLower(string(user))
	transaction := func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(accountName))
		if bucket == nil {
			return fmt.Errorf("no such boltdb bucket named: %s", accountName)
		}
		return nil
	}
	err = b.db.View(transaction)
	if err != nil {
		return nil, fmt.Errorf("invalid POP3 user name: '%s'", user)
	}
	return Pop3BackendSession{
		db:          db,
		accountName: accountName,
	}, nil
}

// Pop3Service is a pop3 service which is backed by
// a local boltdb
type Pop3Service struct {
	db *bolt.DB
}

// NewPop3Service creates a new Pop3Service
// with the given boltdb filename
func NewPop3Service(db *bolt.DB) *Pop3Service {
	p := Pop3Service{
		db: *bolt.DB,
	}
	return &p
}

// HandleConnection is a blocking function that uses the given
// connection to handle a pop3 session
func (p *Pop3Service) HandleConnection(conn net.Conn) error {
	defer conn.Close()
	backend := NewPop3Backend(p.db)
	pop3Session := pop3.NewSession(conn, backend)
	pop3Session.Serve()
	return nil
}
