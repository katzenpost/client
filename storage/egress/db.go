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
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/boltdb/bolt"
	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/crypto/block"
	sphinxconstants "github.com/katzenpost/core/sphinx/constants"
)

const (
	EgressBucketName = "outgoing"
	BlockIDLength    = 8
)

// StorageBlock contains an encrypted message fragment
// and other fields needed to send it to the destination
// XXX todo: finish this source file... conversion to and from json.
type StorageBlock struct {
	BlockID           [BlockIDLength]byte
	Sender            string
	SenderProvider    string
	Recipient         string
	RecipientProvider string
	RecipientID       [sphinxconstants.RecipientIDLength]byte
	SendAttempts      uint8
	SURBKeys          []byte
	SURBID            [sphinxconstants.SURBIDLength]byte
	Block             block.Block
}

// JsonStorageBlock is a json serializable representation of StorageBlock
type JsonStorageBlock struct {
	BlockID           string
	Sender            string
	SenderProvider    string
	Recipient         string
	RecipientProvider string
	RecipientID       string
	SendAttempts      int
	SURBKeys          string
	SURBID            string
	JsonBlock         *block.JsonBlock
}

// StorageBlock method returns a *StorageBlock or error
// given the JsonStorageBlock receiver struct
func (j *JsonStorageBlock) ToStorageBlock() (*StorageBlock, error) {
	recipientID, err := base64.StdEncoding.DecodeString(j.RecipientID)
	if err != nil {
		return nil, err
	}
	blockID, err := base64.StdEncoding.DecodeString(j.BlockID)
	if err != nil {
		return nil, err
	}
	surbID, err := base64.StdEncoding.DecodeString(j.SURBID)
	if err != nil {
		return nil, err
	}
	surbKeys, err := base64.StdEncoding.DecodeString(j.SURBKeys)
	if err != nil {
		return nil, err
	}
	b, err := j.JsonBlock.ToBlock()
	if err != nil {
		return nil, err
	}
	s := StorageBlock{
		Sender:            j.Sender,
		SenderProvider:    j.SenderProvider,
		Recipient:         j.Recipient,
		RecipientProvider: j.RecipientProvider,
		SendAttempts:      uint8(j.SendAttempts),
		Block:             *b,
	}
	copy(s.BlockID[:], blockID)
	copy(s.RecipientID[:], recipientID)
	copy(s.SURBKeys[:], surbKeys)
	copy(s.SURBID[:], surbID)
	return &s, nil
}

// JsonStorageBlock returns a *JsonStorageBlock
// given the StorageBlock receiver struct
func (s *StorageBlock) ToJsonStorageBlock() *JsonStorageBlock {
	j := JsonStorageBlock{
		BlockID:           base64.StdEncoding.EncodeToString(s.BlockID[:]),
		Sender:            s.Sender,
		SenderProvider:    s.SenderProvider,
		Recipient:         s.Recipient,
		RecipientProvider: s.RecipientProvider,
		RecipientID:       base64.StdEncoding.EncodeToString(s.RecipientID[:]),
		SendAttempts:      int(s.SendAttempts),
		SURBKeys:          base64.StdEncoding.EncodeToString(s.SURBKeys[:]),
		SURBID:            base64.StdEncoding.EncodeToString(s.SURBID[:]),
		JsonBlock:         s.Block.ToJsonBlock(),
	}
	return &j
}

// Bytes returns the given StorageBlock receiver struct
// into a byte slice of json
func (s *StorageBlock) ToBytes() ([]byte, error) {
	j := s.ToJsonStorageBlock()
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
	s, err := j.ToStorageBlock()
	return s, err
}

// Store handles getting and putting message fragments
// in our persistent db store
type Store struct {
	db *bolt.DB
}

// New returns a new *Store or an error
func New(dbname string) (*Store, error) {
	o := Store{}
	var err error
	o.db, err = bolt.Open(dbname, 0600, &bolt.Options{Timeout: constants.DatabaseConnectTimeout})
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// Close closes our Store database
func (o *Store) Close() error {
	err := o.db.Close()
	return err
}

// Put puts a given StorageBlock into our db
// and returns a block ID which is it's key
func (o *Store) Put(b *StorageBlock) (*[BlockIDLength]byte, error) {
	blockID := [BlockIDLength]byte{}
	transaction := func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(EgressBucketName))
		if err != nil {
			return err
		}
		// Generate ID for the StorageBlock.
		// This returns an error only if the Tx is closed or not writeable.
		// That can't happen in an Update() call so I ignore the error check.
		id, _ := bucket.NextSequence()
		binary.BigEndian.PutUint64(blockID[:], id)
		b.BlockID = blockID
		value, err := b.ToBytes()
		if err != nil {
			return err
		}

		err = bucket.Put(blockID[:], value)
		return err
	}
	err := o.db.Update(transaction)
	if err != nil {
		return nil, err
	}
	return &blockID, nil
}

func (o *Store) Update(blockID *[BlockIDLength]byte, b *StorageBlock) error {
	transaction := func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(EgressBucketName))
		if bucket == nil {
			return errors.New("Update failed to get the bucket")
		}
		value, err := b.ToBytes()
		if err != nil {
			return err
		}
		err = bucket.Put(blockID[:], value)
		return err
	}
	err := o.db.Update(transaction)
	return err
}

// GetKeys returns all the keys currently in the database
func (o *Store) GetKeys() ([][BlockIDLength]byte, error) {
	keys := [][BlockIDLength]byte{}
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(EgressBucketName))
		if b == nil {
			return errors.New("GetKeys failed to get the bucket")
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			blockid := [BlockIDLength]byte{}
			copy(blockid[:], k)
			keys = append(keys, blockid)
		}
		return nil
	}
	err := o.db.View(transaction)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (o *Store) Get(blockID *[BlockIDLength]byte) ([]byte, error) {
	var err error
	ret := []byte{}
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(EgressBucketName))
		v := b.Get(blockID[:])
		ret = make([]byte, len(v))
		copy(ret, v)
		return err
	}
	err = o.db.View(transaction)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Remove removes a specific *StorageBlock from our db
// specified by the SURB ID
func (o *Store) Remove(blockID *[BlockIDLength]byte) error {
	var err error
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(EgressBucketName))
		err := b.Delete(blockID[:])
		return err
	}

	err = o.db.Update(transaction)
	if err != nil {
		return err
	}
	return nil
}
