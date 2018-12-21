// queue.go - Client egress queue.
// Copyright (C) 2018  masala, David Stainton.
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
	"errors"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/katzenpost/core/queue"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/worker"
	"gopkg.in/op/go-logging.v1"
)

// ARQ is the struct type that keeps state for reliable message delivery.
type ARQ struct {
	sync.Mutex
	worker.Worker

	log *logging.Logger

	queue *queue.PriorityQueue
	s     *Session

	ingressChan chan *Message
	removeMap   map[[sConstants.SURBIDLength]byte]bool

	clock clockwork.Clock
}

// NewARQ makes a new ARQ and starts the worker thread.
func NewARQ(s *Session, log *logging.Logger) *ARQ {
	a := &ARQ{
		log:         log,
		s:           s,
		queue:       queue.New(),
		clock:       clockwork.NewRealClock(),
		ingressChan: make(chan *Message),
		removeMap:   make(map[[sConstants.SURBIDLength]byte]bool),
	}
	a.Go(a.worker)
	return a
}

// Enqueue adds a message to the ARQ
func (a *ARQ) Enqueue(m *Message) error {
	if m == nil {
		return errors.New("error, nil Message")
	}
	a.ingressChan <- m
	a.log.Debugf("Enqueue msg[%x]", m.ID)
	return nil
}

// Remove removes the item with the given SURB ID.
func (a *ARQ) Remove(surbID [sConstants.SURBIDLength]byte) {
	a.Lock()
	a.removeMap[surbID] = true
	a.Unlock()
}

func (a *ARQ) pushEgress(mesg *Message) {
	// XXX should lock m
	if len(mesg.Reply) > 0 {
		// Already ACK'd
		return
	}
	a.log.Debugf("Rescheduling msg[%x]", mesg.ID)
	a.s.egressQueueLock.Lock()
	err := a.s.egressQueue.Push(mesg)
	a.s.egressQueueLock.Unlock()
	if err != nil {
		panic(err)
	}
}

func (a *ARQ) worker() {
	for {
		a.log.Debugf("Loop0")
		var c <-chan time.Time

		if m := a.queue.Peek(); m != nil {
			msg := m.Value.(*Message)
			a.Lock()
			_, ok := a.removeMap[*msg.SURBID]
			a.Unlock()
			if ok {
				_ = a.queue.Pop()
				continue
			}
			tl := msg.timeLeft(a.clock)
			if tl < 0 {
				a.log.Debugf("Queue behind schedule %v", tl)
				raw := a.queue.Pop()
				mesg := raw.Value.(*Message)

				a.pushEgress(mesg)
				continue
			} else {
				a.log.Debugf("Setting timer for msg[%x]: %d", msg.ID, tl)
				c = a.clock.After(tl)
			}
		} else {
			a.log.Debug("Nothing in queue")
		}

		select {
		case <-a.s.HaltCh():
			a.log.Debugf("Terminating gracefully")
			return
		case <-c:
			a.log.Debugf("Timer fired at %s", a.clock.Now())
			raw := a.queue.Pop()
			mesg := raw.Value.(*Message)
			if mesg == nil {
				a.log.Debug("weird")
				continue
			}
			a.pushEgress(mesg)
		case message := <-a.ingressChan:
			a.queue.Enqueue(message.expiry(), message)
		}
	}
}
