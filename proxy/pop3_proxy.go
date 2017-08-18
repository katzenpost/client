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
)

type Pop3BackendSession struct {
	db          *bolt.DB
	accountName string
}

func (s Pop3BackendSession) Messages() ([][]byte, error) {
	messages := [][]byte{}
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(s.accountName))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			messages = append(messages, v)
		}
		return nil
	}
	err := s.db.View(transaction)
	if err != nil {
		return nil, err
	}
	return messages, nil
}

func (s Pop3BackendSession) deleteMessage(item int) error {
	var err error
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(s.accountName))
		err := b.Delete([]byte(strconv.Itoa(item)))
		return err
	}
	err = s.db.Update(transaction)
	if err != nil {
		return err
	}
	return nil
}

func (s Pop3BackendSession) DeleteMessages(items []int) error {
	for _, x := range items {
		err := s.deleteMessage(x)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s Pop3BackendSession) Close() {
}

type Pop3Backend struct {
	db *bolt.DB
}

func (b Pop3Backend) NewSession(user, pass []byte) (pop3.BackendSession, error) {
	accountName := strings.ToLower(string(user))
	transaction := func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(accountName))
		if bucket == nil {
			return fmt.Errorf("no such boltdb bucket named: %s", accountName)
		}
		return nil
	}
	err := b.db.View(transaction)
	if err != nil {
		return nil, fmt.Errorf("invalid POP3 user name: '%s'", user)
	}
	return Pop3BackendSession{
		db:          b.db,
		accountName: accountName,
	}, nil
}

type Pop3Proxy struct {
	db *bolt.DB
}

func NewPop3Proxy(dbfile string) (*Pop3Proxy, error) {
	var err error
	p := Pop3Proxy{}
	p.db, err = bolt.Open(dbfile, 0600, &bolt.Options{Timeout: constants.DatabaseConnectTimeout})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Pop3Proxy) HandleConnection(conn net.Conn) error {
	defer conn.Close()
	backend := Pop3Backend{
		db: p.db,
	}
	pop3Session := pop3.NewSession(conn, backend)
	pop3Session.Serve()
	return nil
}
