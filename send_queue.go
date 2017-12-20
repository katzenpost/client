// send_queue.go - send queue with constant time send scheduler
// Copyright (C) 2017  David Stainton
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

// Package client provides the Katzenpost midclient
package client

import (
	"fmt"
	"time"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/minclient"
	"github.com/op/go-logging"
	lane "gopkg.in/oleiade/lane.v1"
)

const RTTSlop = time.Second * 30

// SendQueue
type SendQueue struct {
	worker.Worker

	log          *logging.Logger
	queue        *lane.Queue
	sendDelay    time.Duration
	arqScheduler *ARQScheduler
	minclient    *minclient.Client
	session      *Session
}

func NewSendQueue(logBackend *log.Backend, name string, storage Storage, sendDelay time.Duration, mclient *minclient.Client, session *Session) *SendQueue {
	s := SendQueue{
		log:       logBackend.GetLogger(fmt.Sprintf("SendQueue_%s", name)),
		queue:     lane.NewQueue(),
		sendDelay: sendDelay,
		minclient: mclient,
	}
	arqScheduler := NewARQScheduler(logBackend, name, storage, &s)
	s.arqScheduler = arqScheduler
	return &s
}

func (s *SendQueue) Start() {
	s.log.Debug("Start")
	s.Go(s.sendWorker)
}

func (s *SendQueue) sendWorker() {
	var err error
	var doSend bool
	var surbKeys []byte
	var rtt time.Duration

	s.log.Debug("sendWorker")
	for {
		select {
		case <-time.After(s.sendDelay):
			doSend = true
		case <-s.HaltCh():
			s.log.Debug("halting")
			return
		}
		if doSend {
			if s.queue.Head() == nil {
				s.log.Debug("send queue is empty, nothing to send (decoy traffic not yet implemented)")
				continue
			}
			s.log.Debug("sending a message from the send queue")
			item := s.queue.Dequeue()
			egressBlock, ok := item.(EgressBlock)
			if !ok {
				s.log.Error("failure: Dequeued item is not a EgressBlock")
				continue
			}
			if egressBlock.ReliableSend {
				surbKeys, rtt, err = s.minclient.SendCiphertext(egressBlock.Recipient, egressBlock.Provider, egressBlock.SURBID, egressBlock.Payload)
				if err != nil {
					s.log.Errorf("minclient.SendCiphertext failure: %s", err)
				} else {
					manifest := EgressBlock{
						SURBID:     egressBlock.SURBID,
						Expiration: time.Now().Add(rtt + RTTSlop), // XXX correcto?
						SURBKeys:   surbKeys,
					}
					s.session.AddSURBKeys(egressBlock.SURBID, &manifest)
				}
				// schedule a retransmission
				// XXX FIX ME: rtt + s.retrieveInterval
				s.arqScheduler.ScheduleSend(rtt+s.sendDelay, &egressBlock)
			} else {
				err = s.minclient.SendUnreliableCiphertext(egressBlock.Recipient, egressBlock.Provider, egressBlock.Payload)
				if err != nil {
					s.log.Errorf("minclient.SendUnreliableCiphertext failure: %s", err)
				}
			}
		}
	}
}

func (s *SendQueue) Enqueue(egressBlock *EgressBlock) {
	s.log.Debug("Enqueue")
	s.queue.Enqueue(egressBlock)
}
