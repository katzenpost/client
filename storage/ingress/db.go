// db.go - durable ingress queue
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

package ingress

import (
	"github.com/boltdb/bolt"
	"github.com/katzenpost/client/constants"
)

// Store is our persistent storage for incoming
// messages which have been reassembled.
type Store struct {
	db *bolt.DB
}

// NewStore returns a new *Store or an error
func NewStore(dbFile string) (*Store, error) {
	var err error
	s := Store{}
	s.db, err = bolt.Open(dbFile, 0600, &bolt.Options{Timeout: constants.DatabaseConnectTimeout})
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Messages returns a list of messages stored in our
// bolt database
func (s *Store) Messages() ([][]byte, error) {
	messages := [][]byte{}
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(s.accountName))
		if b == nil {
			return errors.New("boltdb bucket for that account doesn't exist")
		}
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

// deleteMessage deletes a single message from
// our backing database storage
func (s *Store) deleteMessage(item int) error {
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

// DeleteMessages deletes a list of messages
func (s *Store) DeleteMessages(items []int) error {
	for _, x := range items {
		err := s.deleteMessage(x)
		if err != nil {
			return err
		}
	}
	return nil
}
