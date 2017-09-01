// send.go - mix network client send
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

package proxy

import (
	"time"

	"github.com/katzenpost/client/crypto/block"
	"github.com/katzenpost/client/path_selection"
	"github.com/katzenpost/client/scheduler"
	"github.com/katzenpost/client/session_pool"
	"github.com/katzenpost/client/storage"
	"github.com/katzenpost/client/user_pki"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/wire/commands"
)

const (
	RoundTripTimeSlop = 3 * time.Minute // XXX fix me
)

// Sender is used to send a message over the mixnet
type Sender struct {
	identity     string
	pool         *session_pool.SessionPool
	store        *storage.Store
	routeFactory *path_selection.RouteFactory
	userPKI      user_pki.UserPKI
	handler      *block.Handler
}

// NewSender creates a new Sender
func NewSender(identity string, pool *session_pool.SessionPool, store *storage.Store, routeFactory *path_selection.RouteFactory, userPKI user_pki.UserPKI, handler *block.Handler) *Sender {
	s := Sender{
		identity:     identity,
		pool:         pool,
		store:        store,
		routeFactory: routeFactory,
		userPKI:      userPKI,
		handler:      handler,
	}
	return &s
}

// composeSphinxPacket creates a SendPacket wire protocol command with
// a Sphinx packet and SURB header
func (s *Sender) composeSphinxPacket(blockID *[storage.BlockIDLength]byte, storageBlock *storage.StorageBlock, payload []byte) (*commands.SendPacket, time.Duration, error) {
	forwardPath, replyPath, surbID, rtt, err := s.routeFactory.Build(storageBlock.SenderProvider, storageBlock.RecipientProvider, storageBlock.RecipientID)
	if err != nil {
		return nil, rtt, err
	}
	surb, surbKeys, err := sphinx.NewSURB(rand.Reader, replyPath)
	if err != nil {
		return nil, rtt, err
	}
	storageBlock.SURBKeys = surbKeys
	storageBlock.SendAttempts += 1
	storageBlock.SURBID = *surbID
	err = s.store.Update(blockID, storageBlock)
	if err != nil {
		return nil, rtt, err
	}
	sphinxPacket, err := sphinx.NewPacket(rand.Reader, forwardPath, append(surb, payload...))
	if err != nil {
		return nil, rtt, err
	}
	cmd := commands.SendPacket{
		SphinxPacket: sphinxPacket,
	}
	return &cmd, rtt, nil
}

// Send sends an encrypted block over the mixnet
func (s *Sender) Send(blockID *[storage.BlockIDLength]byte, storageBlock *storage.StorageBlock) (time.Duration, error) {
	var rtt time.Duration
	receiverKey, err := s.userPKI.GetKey(storageBlock.Recipient)
	if err != nil {
		return rtt, err
	}
	blockCiphertext := s.handler.Encrypt(receiverKey, &storageBlock.Block)
	cmd, rtt, err := s.composeSphinxPacket(blockID, storageBlock, blockCiphertext)
	if err != nil {
		return rtt, err
	}
	session, mutex, err := s.pool.Get(s.identity)
	if err != nil {
		return rtt, err
	}
	mutex.Lock()
	defer mutex.Unlock()
	err = session.SendCommand(cmd)
	if err != nil {
		return rtt, err
	}
	return rtt, nil
}

// SendScheduler is used to send messages and schedule the retransmission
// if the ACK wasn't received in time
type SendScheduler struct {
	sched        *scheduler.PriorityScheduler
	senders      map[string]*Sender
	store        *storage.Store
	cancellation map[[constants.SURBIDLength]byte]bool
}

// NewSendScheduler creates a new SendScheduler which is used
// to implement our Stop and Wait ARQ for sending messages
// on behalf of one or more user identities
func NewSendScheduler(senders map[string]*Sender, store *storage.Store) *SendScheduler {
	s := SendScheduler{
		senders:      senders,
		cancellation: make(map[[constants.SURBIDLength]byte]bool),
	}
	s.sched = scheduler.New(s.handleSend)
	return &s
}

// Send sends the given block and adds a retransmit job to the scheduler
func (s *SendScheduler) Send(sender string, blockID *[storage.BlockIDLength]byte, storageBlock *storage.StorageBlock) error {
	rtt, err := s.senders[sender].Send(blockID, storageBlock)
	if err != nil {
		return err
	}
	// schedule a resend in the future
	// (but it can be cancelled if we receive an ACK)
	s.add(rtt, storageBlock)
	return nil
}

// add adds a retransmit job to the scheduler
func (s *SendScheduler) add(rtt time.Duration, storageBlock *storage.StorageBlock) {
	s.sched.Add(rtt+RoundTripTimeSlop, storageBlock)
}

// Cancel ensures that a given retransmit will not be executed
func (s *SendScheduler) Cancel(id [constants.SURBIDLength]byte) {
	s.cancellation[id] = true
}

// handleSend is called by the scheduler to perform
// a retransmit
func (s *SendScheduler) handleSend(task interface{}) {
	storageBlock, ok := task.(*storage.StorageBlock)
	if !ok {
		log.Error("SendScheduler got invalid task from priority scheduler.")
		return
	}
	_, ok = s.cancellation[storageBlock.SURBID]
	if !ok {
		rtt, err := s.senders[storageBlock.Sender].Send(&storageBlock.BlockID, storageBlock)
		if err != nil {
			log.Error(err)
		}
		s.add(rtt, storageBlock)
	}
}
