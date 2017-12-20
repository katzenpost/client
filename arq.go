// arq.go - mixnet client Stop and Wait ARQ scheduler
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
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/client/scheduler"
	"github.com/katzenpost/core/log"
	sphinxConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/op/go-logging"
)

// ARQScheduler implements a Stop and Wait ARQ protocol scheme
type ARQScheduler struct {
	log          *logging.Logger
	sched        *scheduler.PriorityScheduler
	cancellation map[[sphinxConstants.SURBIDLength]byte]bool
	storage      Storage
	sendQueue    *SendQueue
}

// NewARQScheduler returns a new ARQScheduler
func NewARQScheduler(logBackend *log.Backend, name string, storage Storage, sendQueue *SendQueue) *ARQScheduler {
	a := ARQScheduler{
		log:          logBackend.GetLogger(fmt.Sprintf("ARQScheduler_%s", name)),
		cancellation: make(map[[sphinxConstants.SURBIDLength]byte]bool),
		storage:      storage,
		sendQueue:    sendQueue,
	}
	a.sched = scheduler.New(a.send, logBackend, name)
	return &a
}

// CancelRetransmission cancels the scheduled retransmission
func (a *ARQScheduler) CancelRetransmission(surbid *[sphinxConstants.SURBIDLength]byte) error {
	a.log.Debug("CancelRetransmission")
	isCancelled, ok := a.cancellation[*surbid]
	if !ok {
		a.log.Error("cancellation failure, surbid not found")
		return errors.New("cancellation failure, surbid not found")
	}
	if isCancelled {
		a.log.Debugf("WTF: retransmission already cancelled with SURB ID %x", *surbid)
	} else {
		a.cancellation[*surbid] = true
	}
	return nil
}

// ScheduleSend adds a send manifest to the priority scheduler with the given
// time duration whence after which this scheduler will push the send manifest
// on the constant time send scheduler's FIFO queue.
func (a *ARQScheduler) ScheduleSend(whence time.Duration, egressBlock *EgressBlock) {
	a.sched.Add(whence, egressBlock)
}

// send is called by our priority queue when a given item should be sent.
func (a *ARQScheduler) send(item interface{}) {
	if manifest, ok := item.(*EgressBlock); ok {
		a.sendQueue.Enqueue(manifest)
	} else {
		a.log.Error("failure: Send received an invalid item to send")
	}
}
