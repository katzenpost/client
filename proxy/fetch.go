// fetch.go - client message retrieval
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
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/client/crypto/block"
	"github.com/katzenpost/client/scheduler"
	"github.com/katzenpost/client/session_pool"
	"github.com/katzenpost/client/storage"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/core/wire/commands"
	"github.com/op/go-logging"
)

// Fetcher fetches messages for a given account identity
type Fetcher struct {
	log       *logging.Logger
	Identity  string
	sequence  uint32
	pool      *session_pool.SessionPool
	store     *storage.Store
	scheduler *SendScheduler
	handler   *block.Handler
}

func NewFetcher(logBackend *log.Backend, identity string, pool *session_pool.SessionPool, store *storage.Store, scheduler *SendScheduler, handler *block.Handler) *Fetcher {
	return &Fetcher{
		log:       logBackend.GetLogger(fmt.Sprintf("Fetcher-%s", identity)),
		Identity:  identity,
		pool:      pool,
		store:     store,
		scheduler: scheduler,
		handler:   handler,
	}
}

// Fetch fetches a message and returns
// the queue size hint or an error.
// The fetched message is then handled
// by either storing it in the DB or
// by cancelling a retransmit if it's an ACK message
func (f *Fetcher) Fetch() (uint8, error) {
	var queueHintSize uint8
	session, mutex, err := f.pool.Get(f.Identity)
	if err != nil {
		f.log.Debugf("Failed to get session from pool: %s", err)
		return uint8(0), err
	}
	mutex.Lock()
	defer mutex.Unlock()
	cmd := commands.RetrieveMessage{
		Sequence: f.sequence,
	}
	err = session.SendCommand(cmd)
	if err != nil {
		f.log.Debugf("SendCommand failed: %s", err)
		return uint8(0), err
	}
	rSeq := uint32(0)
	recvCmd, err := session.RecvCommand()
	if err != nil {
		f.log.Debugf("RecvCommand failed: %s", err)
		return uint8(0), err
	}
	switch cmd := recvCmd.(type) {
	case *commands.MessageACK:
		f.log.Debug("retrieved MessageACK")
		queueHintSize = cmd.QueueSizeHint
		rSeq = cmd.Sequence
		err := f.processAck(cmd.ID, cmd.Payload)
		if err != nil {
			return uint8(0), err
		}
	case *commands.Message:
		f.log.Debug("retrieved Message")
		queueHintSize = cmd.QueueSizeHint
		rSeq = cmd.Sequence
		err := f.processMessage(cmd.Payload)
		if err != nil {
			return uint8(0), err
		}
	case *commands.MessageEmpty:
		f.log.Debug("retreived MessageEmpty")
		return 0, nil
	default:
		err := errors.New("retrieved non-Message/MessageACK wire protocol command")
		f.log.Debug(err)
		return uint8(0), err
	}
	if rSeq != f.sequence {
		err := errors.New("received sequence mismatch")
		f.log.Debug(err)
		return uint8(0), err
	}
	f.sequence += 1
	return queueHintSize, nil
}

// processAck is used by our Stop and Wait ARQ to cancel
// the retransmit timer
func (f *Fetcher) processAck(id [constants.SURBIDLength]byte, payload []byte) error {
	// Ensure payload bytes are all zeros.
	// see Panoramix Mix Network End-to-end Protocol Specification
	// https://github.com/Katzenpost/docs/blob/master/specs/end_to_end.txt
	// Section 4.2.2 Client Protocol Acknowledgment Processing (SURB-ACKs).
	if !utils.CtIsZero(payload) {
		return errors.New("ACK payload bytes are not all 0x00")
	}
	f.scheduler.Cancel(id)
	return nil
}

// processMessage receives a message Block, decrypts it and
// writes it to our local bolt db for eventual processing.
func (f *Fetcher) processMessage(payload []byte) error {
	// XXX for now we ignore the peer identity
	b, _, err := f.handler.Decrypt(payload)
	if err != nil {
		return err
	}
	s := [32]byte{}
	// XXX or should we use the sender's static public key
	// returned from the above Decrypt operation instead of
	// the slice of the ciphertext payload?
	copy(s[:], payload[47:79])
	ingressBlock := storage.IngressBlock{
		S:     s,
		Block: b,
	}
	err = f.store.PutIngressBlock(f.Identity, &ingressBlock)
	if err != nil {
		return err
	}
	ingressBlocks, blockKeys, err := f.store.GetIngressBlocks(f.Identity, b.MessageID)
	if err != nil {
		return err
	}
	ingressBlocks = deduplicateBlocks(ingressBlocks)
	if len(ingressBlocks) == int(b.TotalBlocks) {
		if !validBlocks(ingressBlocks) {
			return errors.New("one or more blocks are invalid")
		}
		message, err := reassembleMessage(ingressBlocks)
		if err != nil {
			return err
		}
		err = f.store.PutMessage(f.Identity, message)
		if err != nil {
			return err
		}
		err = f.store.RemoveBlocks(f.Identity, blockKeys)
		return err
	}
	return nil
}

// FetchScheduler is scheduler which is used to periodically
// fetch messages using a set of fetchers
type FetchScheduler struct {
	log      *logging.Logger
	fetchers map[string]*Fetcher
	sched    *scheduler.PriorityScheduler
	duration time.Duration
}

// NewFetchScheduler creates a new FetchScheduler
// given a slice of identity strings and a duration
func NewFetchScheduler(logBackend *log.Backend, fetchers map[string]*Fetcher, duration time.Duration) *FetchScheduler {
	s := FetchScheduler{
		log:      logBackend.GetLogger("FetchScheduler"),
		fetchers: fetchers,
		duration: duration,
	}
	s.sched = scheduler.New(s.handleFetch)
	return &s
}

// Start starts our periodic message checking scheduler
func (s *FetchScheduler) Start() {
	s.log.Debug("Starting")
	for _, fetcher := range s.fetchers {
		s.log.Debugf("Adding fetcher with cyclic duration %v", s.duration)
		s.sched.Add(s.duration, fetcher.Identity)
	}
}

// Shutdown shuts down the scheduler
func (s *FetchScheduler) Shutdown() {
	s.log.Debug("Shutting down")
	s.sched.Shutdown()
}

// handleFetch is called by the our scheduler when
// a fetch must be performed. After the fetch, we
// either schedule an immediate another fetch or a
// delayed fetch depending if there are more messages left.
// See "Panoramix Mix Network End-to-end Protocol Specification"
// https://github.com/Katzenpost/docs/blob/master/specs/end_to_end.txt
func (s *FetchScheduler) handleFetch(task interface{}) {
	identity, ok := task.(string)
	if !ok {
		s.log.Error("FetchScheduler got invalid task from priority scheduler.")
		return
	}
	s.log.Debugf("handleFetch for identity: %s", identity)
	fetcher, ok := s.fetchers[identity]
	if !ok {
		err := errors.New("fetcher identity not found")
		s.log.Error(err)
		return
	}
	queueSizeHint, err := fetcher.Fetch()
	if err != nil {
		s.log.Error(err)
		return
	}
	if queueSizeHint == 0 {
		s.log.Debugf("%s queueSizeHint is zero, scheduling next fetch in %v seconds", identity, s.duration)
		s.sched.Add(s.duration, identity)
	} else {
		s.log.Debugf("%s queueSizeHing is %d, scheduling next fetch immediately.", identity, queueSizeHint)
		s.sched.Add(time.Duration(0), identity)
	}
	return
}
