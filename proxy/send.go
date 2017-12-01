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
	"fmt"
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
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/sphinx"
	sphinxConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/wire/commands"
	"github.com/op/go-logging"
)

// Sender is used to send a message over the mixnet
type Sender struct {
	identity     string
	pool         *session_pool.SessionPool
	store        *storage.Store
	routeFactory *path_selection.RouteFactory
	userPKI      user_pki.UserPKI
	handler      *block.Handler
	log          *logging.Logger
}

// NewSender creates a new Sender
func NewSender(logBackend *log.Backend, identity string, pool *session_pool.SessionPool, store *storage.Store, routeFactory *path_selection.RouteFactory, userPKI user_pki.UserPKI, handler *block.Handler) (*Sender, error) {
	s := Sender{
		identity:     identity,
		pool:         pool,
		store:        store,
		routeFactory: routeFactory,
		userPKI:      userPKI,
		handler:      handler,
		log:          logBackend.GetLogger(fmt.Sprintf("Sender-%s", identity)),
	}
	s.log.Debugf("New Sender created.")
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
	// if len(sphinxPacket) != coreconstants.PacketLength {
	// 	return nil, rtt, fmt.Errorf("invalid Sphinx packet size: %v want size: %v", len(sphinxPacket), coreconstants.PacketLength)
	// }
	cmd := commands.SendPacket{
		SphinxPacket: sphinxPacket,
	}
	return &cmd, rtt, nil
}

// Send sends an encrypted block over the mixnet
func (s *Sender) Send(blockID *[storage.BlockIDLength]byte, storageBlock *storage.EgressBlock) (time.Duration, error) {
	s.log.Debug("Send: Sending message block...")
	var rtt time.Duration
	session, mutex, err := s.pool.Get(s.identity)
	if err != nil {
		s.log.Debugf("Failed to get session for %s: %s", s.identity, err)
		return rtt, err
	}
	s.log.Debug("retrieved session")
	receiverKey, err := s.userPKI.GetKey(storageBlock.Recipient)
	if err != nil {
		s.log.Debugf("Failed to get userPKI key for %s: %s", storageBlock.Recipient, err)
		return rtt, err
	}
	blockCiphertext, err := s.handler.Encrypt(receiverKey, &storageBlock.Block)
	if err != nil {
		s.log.Debugf("Failed to encrypt block: %s", err)
		return rtt, err
	}
	s.log.Debug("encrypted message block")
	cmd, rtt, err := s.composeSphinxPacket(blockID, storageBlock, blockCiphertext)
	if err != nil {
		s.log.Debugf("Failed to compose Sphinx packet: %s", err)
		return rtt, err
	}
	s.log.Debug("composed sphinx packet")
	mutex.Lock()
	defer mutex.Unlock()
	err = session.SendCommand(cmd)
	if err != nil {
		s.log.Debugf("SendCommand failed: %s", err)
		return rtt, err
	}
	s.log.Debug("sphinx packet sent!")
	return rtt, nil
}

// SendScheduler is used to send messages and schedule the retransmission
// if the ACK wasn't received in time
type SendScheduler struct {
	sync.RWMutex

	log          *logging.Logger
	sched        *scheduler.PriorityScheduler
	senders      map[string]*Sender
	cancellation map[[sphinxConstants.SURBIDLength]byte]bool
}

// NewSendScheduler creates a new SendScheduler which is used
// to implement our Stop and Wait ARQ for sending messages
// on behalf of one or more user identities
func NewSendScheduler(logBackend *log.Backend, senders map[string]*Sender) *SendScheduler {
	s := SendScheduler{
		log:          logBackend.GetLogger("SendScheduler"),
		senders:      senders,
		cancellation: make(map[[sphinxConstants.SURBIDLength]byte]bool),
	}
	s.sched = scheduler.New(s.handleSend, logBackend, "sender")
	return &s
}

// Send sends the given block and adds a retransmit job to the scheduler
func (s *SendScheduler) Send(sender string, blockID *[storage.BlockIDLength]byte, storageBlock *storage.EgressBlock) {
	s.log.Debug("Send")
	rtt, err := s.senders[sender].Send(blockID, storageBlock)
	if err != nil {
		s.log.Debugf("Send failure: %s", err)
		rtt = 10 * time.Second
	}
	// schedule a resend in the future
	// (but it can be cancelled if we receive an ACK)
	s.add(rtt, storageBlock)
}

// add adds a retransmit job to the scheduler
func (s *SendScheduler) add(rtt time.Duration, storageBlock *storage.EgressBlock) {
	s.log.Debug("add begin.")
	s.log.Debugf("schedule a send in %v", rtt+constants.RoundTripTimeSlop)
	s.sched.Add(rtt+constants.RoundTripTimeSlop, storageBlock)
	s.Lock()
	defer s.Unlock()
	s.cancellation[storageBlock.SURBID] = false
	s.log.Debug("add done.")
}

func (s *SendScheduler) isCancelled(id [sphinxConstants.SURBIDLength]byte) bool {
	s.RLock()
	defer s.RUnlock()
	cancelled, ok := s.cancellation[id]
	if ok {
		if cancelled {
			return true
		}
	} else {
		s.log.Error("cancellation map failure")
	}
	return false
}

// Cancel ensures that a given retransmit will not be executed
func (s *SendScheduler) Cancel(id [sphinxConstants.SURBIDLength]byte) {
	s.log.Debug("Cancel")
	if !s.isCancelled(id) {
		s.Lock()
		defer s.Unlock()
		s.cancellation[id] = true
	}
}

// handleSend is called by the scheduler to perform
// a retransmit
func (s *SendScheduler) handleSend(task interface{}) {
	s.log.Debug("handleSend")

	storageBlock, ok := task.(*storage.EgressBlock)
	if !ok {
		s.log.Error("wtf? got invalid task from priority scheduler.")
		return
	}
	if s.isCancelled(storageBlock.SURBID) {
		s.log.Debug("retransmit cancelled!")
	} else {
		s.log.Debug("retransmit not cancelled")
		rtt, err := s.senders[storageBlock.Sender].Send(&storageBlock.BlockID, storageBlock)
		if err != nil {
			s.log.Errorf("Send failure: %s", err)
			rtt = 10 * time.Second
		}
		s.add(rtt, storageBlock)
	}
}

// Shutdown shuts down the send scheduler
func (s *SendScheduler) Shutdown() {
	s.log.Debug("Shutting down")
	s.sched.Shutdown()
}
