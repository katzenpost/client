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
	"encoding/binary"
	"sync"
	"time"

	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/crypto/block"
	"github.com/katzenpost/client/path_selection"
	"github.com/katzenpost/client/scheduler"
	"github.com/katzenpost/client/session_pool"
	"github.com/katzenpost/client/storage"
	"github.com/katzenpost/client/user_pki"
	coreconstants "github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/sphinx"
	sphinxConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
)

// Sender is used to send a message over the mixnet
type Sender struct {
	mutex        *sync.Mutex
	identity     string
	session      wire.SessionInterface
	store        *storage.Store
	routeFactory *path_selection.RouteFactory
	userPKI      user_pki.UserPKI
	handler      *block.Handler
}

// NewSender creates a new Sender
func NewSender(identity string, pool *session_pool.SessionPool, store *storage.Store, routeFactory *path_selection.RouteFactory, userPKI user_pki.UserPKI, handler *block.Handler) (*Sender, error) {
	session, mutex, err := pool.Get(identity)
	if err != nil {
		return nil, err
	}
	s := Sender{
		mutex:        mutex,
		session:      session,
		identity:     identity,
		store:        store,
		routeFactory: routeFactory,
		userPKI:      userPKI,
		handler:      handler,
	}
	return &s, nil
}

// composeSphinxPacket creates a SendPacket wire protocol command with
// a Sphinx packet and SURB header
func (s *Sender) composeSphinxPacket(blockID *[storage.BlockIDLength]byte, storageBlock *storage.EgressBlock, payload []byte) (*commands.SendPacket, time.Duration, error) {
	const (
		hdrLength    = coreconstants.SphinxPlaintextHeaderLength + sphinx.SURBLength
		flagsPadding = 0
		flagsSURB    = 1
		reserved     = 0
	)
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

	// create a valid BlockSphinxPlaintext as specified in the
	// Panoramix Mix Network End-to-end Protocol Specification
	sphinxPlaintextBlock := [coreconstants.ForwardPayloadLength]byte{}
	sphinxPlaintextBlock[0] = flagsSURB
	sphinxPlaintextBlock[1] = reserved
	binary.BigEndian.PutUint16(sphinxPlaintextBlock[coreconstants.SphinxPlaintextHeaderLength:], uint16(len(surb)))
	copy(sphinxPlaintextBlock[coreconstants.SphinxPlaintextHeaderLength:], surb)
	copy(sphinxPlaintextBlock[hdrLength:], payload)

	sphinxPacket, err := sphinx.NewPacket(rand.Reader, forwardPath, sphinxPlaintextBlock[:])
	if err != nil {
		return nil, rtt, err
	}
	cmd := commands.SendPacket{
		SphinxPacket: sphinxPacket,
	}
	return &cmd, rtt, nil
}

// Send sends an encrypted block over the mixnet
func (s *Sender) Send(blockID *[storage.BlockIDLength]byte, storageBlock *storage.EgressBlock) (time.Duration, error) {
	var rtt time.Duration
	receiverKey, err := s.userPKI.GetKey(storageBlock.Recipient)
	if err != nil {
		return rtt, err
	}
	blockCiphertext, err := s.handler.Encrypt(receiverKey, &storageBlock.Block)
	if err != nil {
		return rtt, err
	}
	cmd, rtt, err := s.composeSphinxPacket(blockID, storageBlock, blockCiphertext)
	if err != nil {
		return rtt, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	err = s.session.SendCommand(cmd)
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
	cancellation map[[sphinxConstants.SURBIDLength]byte]bool
}

// NewSendScheduler creates a new SendScheduler which is used
// to implement our Stop and Wait ARQ for sending messages
// on behalf of one or more user identities
func NewSendScheduler(senders map[string]*Sender) *SendScheduler {
	s := SendScheduler{
		senders:      senders,
		cancellation: make(map[[sphinxConstants.SURBIDLength]byte]bool),
	}
	s.sched = scheduler.New(s.handleSend)
	return &s
}

// Send sends the given block and adds a retransmit job to the scheduler
func (s *SendScheduler) Send(sender string, blockID *[storage.BlockIDLength]byte, storageBlock *storage.EgressBlock) error {
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
func (s *SendScheduler) add(rtt time.Duration, storageBlock *storage.EgressBlock) {
	s.sched.Add(rtt+constants.RoundTripTimeSlop, storageBlock)
}

// Cancel ensures that a given retransmit will not be executed
func (s *SendScheduler) Cancel(id [sphinxConstants.SURBIDLength]byte) {
	_, ok := s.cancellation[id]
	if ok {
		if s.cancellation[id] {
			log.Errorf("SendScheduler Cancellation with SURB ID %x already cancelled", id)
		} else {
			s.cancellation[id] = true
		}
	} else {
		log.Error("SendScheduler Cancellation received an unknown SURB ID")
	}
}

// handleSend is called by the scheduler to perform
// a retransmit
func (s *SendScheduler) handleSend(task interface{}) {
	storageBlock, ok := task.(*storage.EgressBlock)
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
