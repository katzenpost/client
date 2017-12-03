// db.go - durable storage for ingress and egress messages
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

package storage

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/coreos/bbolt"
	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/crypto/block"
	sphinxconstants "github.com/katzenpost/core/sphinx/constants"
)

const (
	// BlockIDLength is the length of our storage block IDs
	// which are used to uniquely identify storage blocks
	// in the boltdb ingress buckets
	BlockIDLength = 8

	// EgressBucketName is the name of the boltdb bucket
	// used for storing messages received from our SMTP listener.
	// We intentionally have a single boltdb bucket that handles
	// all the outgoing messages for the client.
	EgressBucketName = "outgoing"
)

// ingressBucketNameFromAccount is a helper function that
// returns the bucket name of the bucket that persists
// encrypted message blocks given the name of an account.
// (in this case the account is an e-mail address)
func ingressBucketNameFromAccount(accountName string) []byte {
	return []byte(fmt.Sprintf("%s_incoming", accountName))
}

// pop3BucketNameFromAccount is a helper function that
// returns the bucket name of the bucket that persists
// plaintext message constructed from one or more
// encrypted blocks from the account's "_incoming" bucket.
func pop3BucketNameFromAccount(accountName string) []byte {
	return []byte(fmt.Sprintf("%s_pop3", accountName))
}

// EgressBlock contains an encrypted message fragment
// and other fields needed to send it to the destination
type EgressBlock struct {
	// BlockID is used to uniquely identify storage blocks
	BlockID [BlockIDLength]byte

	// Sender is the sender identity (aka e-mail address)
	Sender string

	// SenderProvider is the Provider for a given sender.
	// (the part of the email address after the @-sign)
	SenderProvider string

	// Recipient is the recipient identity/e-mail address
	Recipient string

	// RecipientProvider is the Provider name of the recipient
	// (the part of the email address after the @-sign)
	RecipientProvider string

	// RecipientID is the user ID for a given recipient
	// which is padded to fixed length
	RecipientID [sphinxconstants.RecipientIDLength]byte

	// SenderID is the user ID for a given sender
	// which is padded to fixed length
	SenderID [sphinxconstants.RecipientIDLength]byte

	// SendAttempts is the number of attempts to retransmit
	// a given message block
	SendAttempts uint8

	// SURBKeys are the keys used to decrypt a message
	// composed using a SURB. See github.com/katzenpost/core/sphinx
	SURBKeys []byte

	// SURBID is used to uniquely identify a message and decryption keys
	// for a message composed using a SURB.
	SURBID [sphinxconstants.SURBIDLength]byte

	// Block is a message fragment
	Block block.Block
}

// jsonEgressBlock is a json serializable representation of EgressBlock
type jsonEgressBlock struct {
	BlockID           string
	Sender            string
	SenderProvider    string
	Recipient         string
	RecipientProvider string
	RecipientID       string
	SenderID          string
	SendAttempts      int
	SURBKeys          string
	SURBID            string
	JsonBlock         *block.JsonBlock
}

// EgressBlock method returns a *EgressBlock or error
// given the jsonEgressBlock receiver struct
func (j *jsonEgressBlock) ToEgressBlock() (*EgressBlock, error) {
	recipientID, err := base64.StdEncoding.DecodeString(j.RecipientID)
	if err != nil {
		return nil, err
	}
	senderID, err := base64.StdEncoding.DecodeString(j.SenderID)
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
	s := EgressBlock{
		Sender:            j.Sender,
		SenderProvider:    j.SenderProvider,
		Recipient:         j.Recipient,
		RecipientProvider: j.RecipientProvider,
		SendAttempts:      uint8(j.SendAttempts),
		Block:             *b,
	}
	copy(s.BlockID[:], blockID)
	copy(s.RecipientID[:], recipientID)
	copy(s.SenderID[:], senderID)
	copy(s.SURBKeys[:], surbKeys)
	copy(s.SURBID[:], surbID)
	return &s, nil
}

// ToJsonEgressBlock returns a *jsonEgressBlock
// given the EgressBlock receiver struct
func (s *EgressBlock) ToJsonEgressBlock() *jsonEgressBlock {
	j := jsonEgressBlock{
		BlockID:           base64.StdEncoding.EncodeToString(s.BlockID[:]),
		Sender:            s.Sender,
		SenderProvider:    s.SenderProvider,
		Recipient:         s.Recipient,
		RecipientProvider: s.RecipientProvider,
		RecipientID:       base64.StdEncoding.EncodeToString(s.RecipientID[:]),
		SenderID:          base64.StdEncoding.EncodeToString(s.SenderID[:]),
		SendAttempts:      int(s.SendAttempts),
		SURBKeys:          base64.StdEncoding.EncodeToString(s.SURBKeys[:]),
		SURBID:            base64.StdEncoding.EncodeToString(s.SURBID[:]),
		JsonBlock:         s.Block.ToJsonBlock(),
	}
	return &j
}

// Bytes returns the given EgressBlock receiver struct
// into a byte slice of json
func (s *EgressBlock) ToBytes() ([]byte, error) {
	j := s.ToJsonEgressBlock()
	return json.Marshal(j)
}

// FromBytes returns a *EgressBlock or error
// given a byte slice of json data
func EgressBlockFromBytes(raw []byte) (*EgressBlock, error) {
	j := jsonEgressBlock{}
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return nil, err
	}
	s, err := j.ToEgressBlock()
	return s, err
}

// IngressBlock is used to store incoming message blocks retrieved
// from the client's Provider
type IngressBlock struct {
	// S is the `s` value from the noise_x encryption operation
	S [32]byte
	// Block is a serialized block.Block
	Block *block.Block
}

// ToBytes serializes an IngressBlock into a byte slice
func (i *IngressBlock) ToBytes() ([]byte, error) {
	b, err := i.Block.ToBytes()
	if err != nil {
		return nil, err
	}
	b = append(i.S[:], b...)
	return b, nil
}

// IngressBlockFromBytes deserializes a slice of bytes to an IngressBlock
func IngressBlockFromBytes(b []byte) (*IngressBlock, error) {
	aBlock, err := block.FromBytes(b[32:])
	if err != nil {
		return nil, err
	}
	s := [32]byte{}
	copy(s[:], b[0:31])
	ingressBlock := IngressBlock{
		S:     s,
		Block: aBlock,
	}
	return &ingressBlock, nil
}

// Store is our persistent storage for incoming
// messages which have been reassembled.
type Store struct {
	db *bolt.DB
}

// NewStore returns a new *Store or an error
func New(dbFile string) (*Store, error) {
	var err error
	s := Store{}
	s.db, err = bolt.Open(dbFile, 0600, &bolt.Options{Timeout: constants.DatabaseConnectTimeout})
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Close closes our Store database
func (s *Store) Close() error {
	err := s.db.Close()
	return err
}

// egress storage

// Put puts a given EgressBlock into our db
// and returns a block ID which is it's key
func (s *Store) PutEgressBlock(b *EgressBlock) (*[BlockIDLength]byte, error) {
	blockID := [BlockIDLength]byte{}
	transaction := func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(EgressBucketName))
		if err != nil {
			return err
		}
		// Generate ID for the EgressBlock.
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
	err := s.db.Update(transaction)
	if err != nil {
		return nil, err
	}
	return &blockID, nil
}

// Update is used to update a specified storage block
func (s *Store) Update(blockID *[BlockIDLength]byte, b *EgressBlock) error {
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
	err := s.db.Update(transaction)
	return err
}

// GetSURBKeys returns the SURB Keys given a SURB ID
func (s *Store) GetSURBKeys(surbId [sphinxconstants.SURBIDLength]byte) ([]byte, error) {
	SURBKeys := []byte{}
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(EgressBucketName))
		if b == nil {
			return errors.New("GetSURBKeys failed to get the bucket")
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			egressBlock, err := EgressBlockFromBytes(v)
			if err != nil {
				return err
			}
			if bytes.Equal(egressBlock.SURBID[:], surbId[:]) {
				SURBKeys = make([]byte, len(egressBlock.SURBKeys))
				copy(SURBKeys, egressBlock.SURBKeys)
				return nil
			}
		}
		return nil
	}
	err := s.db.View(transaction)
	if err != nil {
		return nil, err
	}
	return SURBKeys, nil
}

// GetKeys returns all the keys currently in the database
func (s *Store) GetKeys() ([][BlockIDLength]byte, error) {
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
	err := s.db.View(transaction)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// Get returns a serialized storage block given a block ID
func (s *Store) Get(blockID *[BlockIDLength]byte) ([]byte, error) {
	var err error
	ret := []byte{}
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(EgressBucketName))
		v := b.Get(blockID[:])
		ret = make([]byte, len(v))
		copy(ret, v)
		return err
	}
	err = s.db.View(transaction)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Remove removes a specific *EgressBlock from our db
// specified by the SURB ID
func (s *Store) Remove(blockID *[BlockIDLength]byte) error {
	var err error
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(EgressBucketName))
		err := b.Delete(blockID[:])
		return err
	}

	err = s.db.Update(transaction)
	if err != nil {
		return err
	}
	return nil
}

// ingress storage

// CreateAccountBuckets is used to create a set of storage account buckets
// that will store received messages
func (s *Store) CreateAccountBuckets(accounts []string) error {
	for _, accountName := range accounts {
		// bucket for blocks, message fragment ciphertext
		transaction := func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists(ingressBucketNameFromAccount(accountName))
			return err
		}
		err := s.db.Update(transaction)
		if err != nil {
			return err
		}

		// bucket for pop3, assembled messages
		transaction = func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists(pop3BucketNameFromAccount(accountName))
			return err
		}
		err = s.db.Update(transaction)
		if err != nil {
			return err
		}
	}
	return nil
}

// Put puts an IngressBlock, into the corresponding bucket for that account
func (s *Store) PutIngressBlock(accountName string, b *IngressBlock) error {
	transaction := func(tx *bolt.Tx) error {
		bucket := tx.Bucket(ingressBucketNameFromAccount(accountName))
		if bucket == nil {
			return fmt.Errorf("ingress store put failure: bucket not found: %s", accountName)
		}
		seq, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		ingressBlockBytes, err := b.ToBytes()
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(strconv.Itoa(int(seq))), ingressBlockBytes)
		return err
	}
	err := s.db.Update(transaction)
	return err
}

// GetIngressBlocks returns a slice of IngressBlocks which contain
// the given message ID for the given account name
// The block "keys" are also returned so that message a message is reassembled
// the blocks can be removed from the db.
func (s *Store) GetIngressBlocks(accountName string, messageID [constants.MessageIDLength]byte) ([]*IngressBlock, [][]byte, error) {
	blocks := []*IngressBlock{}
	keys := [][]byte{}
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket(ingressBucketNameFromAccount(accountName))
		if b == nil {
			return errors.New("boltdb bucket for that account doesn't exist")
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			newVal := make([]byte, len(v))
			copy(newVal, v)
			ingressBlock, err := IngressBlockFromBytes(newVal)
			if err != nil {
				return err
			}
			if ingressBlock.Block.MessageID == messageID {
				blocks = append(blocks, ingressBlock)
				newKey := make([]byte, len(k))
				copy(newKey, k)
				keys = append(keys, newKey)
			}
		}
		return nil
	}
	err := s.db.View(transaction)
	if err != nil {
		return nil, nil, err
	}
	return blocks, keys, nil
}

// RemoveBlocks removes the blocks using the specified keys
func (s *Store) RemoveBlocks(accountName string, keys [][]byte) error {
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket(ingressBucketNameFromAccount(accountName))
		if b == nil {
			return errors.New("boltdb bucket for that account doesn't exist")
		}
		for _, key := range keys {
			err := b.Delete(key)
			if err != nil {
				return err
			}
		}
		return nil
	}
	err := s.db.Update(transaction)
	return err
}

// Messages returns a list of messages stored in our
// bolt database
func (s *Store) Messages(accountName string) ([][]byte, error) {
	messages := [][]byte{}
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket(pop3BucketNameFromAccount(accountName))
		if b == nil {
			return errors.New("boltdb bucket for that account doesn't exist")
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			newVal := make([]byte, len(v))
			copy(newVal, v)
			messages = append(messages, newVal)
		}
		return nil
	}
	err := s.db.View(transaction)
	if err != nil {
		return nil, err
	}
	return messages, nil
}

// PutMessage puts a fully assembled plaintext message into
// the db where it can be retrieved using our pop3 service
func (s *Store) PutMessage(accountName string, message []byte) error {
	var err error
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket(pop3BucketNameFromAccount(accountName))
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		err = b.Put([]byte(strconv.Itoa(int(seq))), message)
		if err != nil {
			return err
		}
		return nil
	}
	err = s.db.Update(transaction)
	if err != nil {
		return err
	}
	return nil

}

// deleteMessage deletes a single message from
// our backing database storage
func (s *Store) deleteMessage(accountName string, item int) error {
	var err error
	transaction := func(tx *bolt.Tx) error {
		b := tx.Bucket(pop3BucketNameFromAccount(accountName))
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
func (s *Store) DeleteMessages(accountName string, items []int) error {
	for _, x := range items {
		err := s.deleteMessage(accountName, x)
		if err != nil {
			return err
		}
	}
	return nil
}
