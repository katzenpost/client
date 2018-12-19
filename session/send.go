// send.go - mixnet client send
// Copyright (C) 2018  David Stainton.
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

package session

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
	cConstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/rand"
	sConstants "github.com/katzenpost/core/sphinx/constants"
)

// Message is a message reference which is used to match future
// received SURB replies.
type Message struct {
	// ID is the message identifier
	ID *[cConstants.MessageIDLength]byte

	// Recipient is the message recipient
	Recipient string

	// Provider is the recipient Provider
	Provider string

	// Payload is the message payload
	Payload []byte

	// SentAt contains the time the message was sent.
	SentAt time.Time

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration

	// SURBID is the SURB identifier.
	SURBID *[sConstants.SURBIDLength]byte

	// Key is the SURB decryption keys
	Key []byte

	// Reply is the SURB reply
	Reply []byte

	// SURBType is the SURB type.
	SURBType int
}

func (m *Message) expiry() uint64 {
	// TODO: add exponential backoff
	return uint64(m.SentAt.Add(m.ReplyETA).UnixNano())
}

func (m *Message) timeLeft(clock clockwork.Clock) time.Duration {
	return m.SentAt.Add(m.ReplyETA).Sub(clock.Now())
}

// WaitForReply blocks until a reply is received.
func (s *Session) WaitForReply(msg *Message) []byte {
	s.mapLock.Lock()
	replyLock := s.replyNotifyMap[*msg.ID]
	s.mapLock.Unlock()
	replyLock.Lock()
	return s.messageIDMap[*msg.ID].Reply
}

func (s *Session) sendNext() error {
	s.egressQueueLock.Lock()
	defer s.egressQueueLock.Unlock()

	var err error = nil
	var msg *Message = nil
	for {
		msg, err = s.egressQueue.Peek()
		if err != nil {
			return err
		}
		if msg.Provider == "" {
			panic("wtf")
		}
	}
	err = s.send(msg)
	if err != nil {
		return err
	}
	_, err = s.egressQueue.Pop()
	return err
}

func (s *Session) send(msg *Message) error {
	var err error

	surbID := [sConstants.SURBIDLength]byte{}
	io.ReadFull(rand.Reader, surbID[:])

	key, eta, err := s.minclient.SendCiphertext(msg.Recipient, msg.Provider, &surbID, msg.Payload)
	if err != nil {
		return err
	}

	msg.Key = key
	msg.SentAt = time.Now()
	msg.ReplyETA = eta
	msg.SURBID = &surbID

	s.mapLock.Lock()
	defer s.mapLock.Unlock()

	s.surbIDMap[surbID] = msg
	s.messageIDMap[*msg.ID] = msg

	return err
}

func (s *Session) sendLoopDecoy() error {
	s.log.Info("sending loop decoy")
	const loopService = "loop"
	serviceDesc, err := s.GetService(loopService)
	if err != nil {
		return err
	}
	payload := [constants.UserForwardPayloadLength]byte{}
	id := [cConstants.MessageIDLength]byte{}
	io.ReadFull(rand.Reader, id[:])
	msg := &Message{
		ID:        &id,
		Recipient: serviceDesc.Name,
		Provider:  serviceDesc.Provider,
		Payload:   payload[:],
	}
	return s.send(msg)
}

// SendUnreliable send a message without any automatic retransmission.
func (s *Session) SendUnreliable(recipient, provider string, message []byte) (*Message, error) {
	s.log.Debugf("Send")
	id := [cConstants.MessageIDLength]byte{}
	io.ReadFull(rand.Reader, id[:])
	var msg = Message{
		ID:        &id,
		Recipient: recipient,
		Provider:  provider,
		Payload:   message,
	}

	s.egressQueueLock.Lock()
	defer s.egressQueueLock.Unlock()

	err := s.egressQueue.Push(&msg)
	return &msg, err
}

// SendKaetzchenQuery sends a mixnet provider-side service query.
func (s *Session) SendKaetzchenQuery(recipient, provider string, message []byte, wantResponse bool) (*Message, error) {
	if provider == "" {
		panic("wtf")
	}
	// Ensure the request message is under the maximum for a single
	// packet, and pad out the message so that it is the correct size.
	if len(message) > constants.UserForwardPayloadLength {
		return nil, fmt.Errorf("invalid message size: %v", len(message))
	}
	payload := make([]byte, constants.UserForwardPayloadLength)
	copy(payload, message)
	id := [cConstants.MessageIDLength]byte{}
	io.ReadFull(rand.Reader, id[:])
	var msg = Message{
		ID:        &id,
		Recipient: recipient,
		Provider:  provider,
		Payload:   payload,
		SURBType:  cConstants.SurbTypeKaetzchen,
	}

	s.mapLock.Lock()
	defer s.mapLock.Unlock()

	s.replyNotifyMap[*msg.ID] = new(sync.Mutex)
	s.replyNotifyMap[*msg.ID].Lock()

	s.egressQueueLock.Lock()
	defer s.egressQueueLock.Unlock()

	err := s.egressQueue.Push(&msg)
	return &msg, err
}
