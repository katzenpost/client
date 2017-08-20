// db.go - durable egress queue
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

package egress

import (
	"encoding/base64"
	"encoding/json"

	"github.com/boltdb/bolt"
	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/core/crypto/rand"
	sphinxconstants "github.com/katzenpost/core/sphinx/constants"
)

const (
	bucketName = "outgoing"
)

// StorageBlock contains an encrypted message fragment
// and other fields needed to send it to the destination
type StorageBlock struct {
	SenderProvider    string
	RecipientProvider string
	RecipientID       *[sphinxconstants.RecipientIDLength]byte
	Payload           []byte
}

// JsonStorageBlock is a json serializable representation of StorageBlock
type JsonStorageBlock struct {
	SenderProvider    string
	RecipientProvider string
	RecipientID       string
	Payload           string
}

// StorageBlock method returns a *StorageBlock or error
// given the JsonStorageBlock receiver struct
func (j *JsonStorageBlock) StorageBlock() (*StorageBlock, error) {
	id, err := base64.StdEncoding.DecodeString(j.RecipientID)
	if err != nil {
		return nil, err
	}
	recipientID := [sphinxconstants.RecipientIDLength]byte{}
	copy(recipientID[:], id)
	payload, err := base64.StdEncoding.DecodeString(j.Payload)
	if err != nil {
		return nil, err
	}
	s := StorageBlock{
		SenderProvider:    j.SenderProvider,
		RecipientProvider: j.RecipientProvider,
		RecipientID:       &recipientID,
		Payload:           payload,
	}
	return &s, nil
}

// JsonStorageBlock returns a *JsonStorageBlock
// given the StorageBlock receiver struct
func (s *StorageBlock) JsonStorageBlock() *JsonStorageBlock {
	j := JsonStorageBlock{
		SenderProvider:    s.SenderProvider,
		RecipientProvider: s.RecipientProvider,
		RecipientID:       base64.StdEncoding.EncodeToString(s.RecipientID[:]),
		Payload:           base64.StdEncoding.EncodeToString(s.Payload),
	}
	return &j
}

// Bytes returns the given StorageBlock receiver struct
// into a byte slice of json
func (s *StorageBlock) Bytes() ([]byte, error) {
	j := s.JsonStorageBlock()
	return json.Marshal(j)
}

// FromBytes returns a *StorageBlock or error
// given a byte slice of json data
func FromBytes(raw []byte) (*StorageBlock, error) {
	j := JsonStorageBlock{}
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return nil, err
	}
	s, err := j.StorageBlock()
	return s, err
}

// OutgoingStore handles getting and putting message fragments
// in our persistent db store
type OutgoingStore struct {
	db *bolt.DB
}

// New returns a new *OutgoingStore or an error
func New(dbname string) (*OutgoingStore, error) {
	o := OutgoingStore{}
	var err error
	o.db, err = bolt.Open(dbname, 0600, &bolt.Options{Timeout: constants.DatabaseConnectTimeout})
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// Close closes our OutgoingStore database
func (o *OutgoingStore) Close() error {
	err := o.db.Close()
	return err
}

// Push pushes a given StorageBlock into our database,
// assigning it a random SURB ID for use as it's key
func (o *OutgoingStore) Push(b *StorageBlock) error {
	surbID := [sphinxconstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	if err != nil {
		return err
	}
	err = o.Put(&surbID, b)
	return err
}

// Put puts a given *StorageBlock into our db with the given surbID
// as it's lookup key
func (o *OutgoingStore) Put(surbID *[sphinxconstants.SURBIDLength]byte, b *StorageBlock) error {
	var err error
	transaction := func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		value, err := b.Bytes()
		if err != nil {
			return err
		}
		err = bucket.Put(surbID[:], value)
		return err
	}
	err = o.db.Update(transaction)
	return err
}

// GetKeys returns all the keys currently in the database
func (o *OutgoingStore) GetKeys() ([][sphinxconstants.SURBIDLength]byte, error) {
	keys := [][sphinxconstants.SURBIDLength]byte{}
	err := o.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			surbid := [sphinxconstants.SURBIDLength]byte{}
			copy(surbid[:], k)
			keys = append(keys, surbid)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// Remove removes a specific *StorageBlock from our db
// specified by the SURB ID
func (o *OutgoingStore) Remove(surbID *[sphinxconstants.SURBIDLength]byte) error {
	var err error
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		err := b.Delete(surbID[:])
		return err
	}

	err = o.db.Update(transaction)
	if err != nil {
		return err
	}
	return nil
}
