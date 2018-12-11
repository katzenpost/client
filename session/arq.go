// queue.go - Client egress queue.
// Copyright (C) 2018  masala.
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
	"sync"
	"time"

	"github.com/katzenpost/core/queue"
	"github.com/katzenpost/core/worker"
)

// ARQ is the struct type that keeps state for reliable message delivery
type ARQ struct {
	sync.Mutex
	sync.Cond
	worker.Worker
	priq queue.PriorityQueue
	s    *Session

	OpCh       chan *MessageRef
	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once
}

func (m *MessageRef) expiry() uint64 {
	// TODO: add exponential backoff
	return uint64(m.SentAt.Add(m.ReplyETA).UnixNano())
}

func (m *MessageRef) timeLeft() time.Duration {
	return m.SentAt.Add(m.ReplyETA).Sub(time.Now())
}

func (a *ARQ) worker() {
	for {
		var mo *MessageRef
		select {
		case <-a.HaltCh():
			a.s.log.Debugf("Terminating gracefully")
			return
		case mo = <-a.opCh:
		}
		a.Lock()
		a.priq.Enqueue(mo.expiry(), mo)
		if a.priq.Len() == 1 {
			a.Broadcast()
		}
		a.Unlock()
	}
}

func (a *ARQ) wakeupCh() chan struct{} {
	c := make(chan struct{})
	go func() {
		defer close(c)
		a.Wait()
	}()
	return c
}

func (a *ARQ) reschedule() {
	a.Lock()
	// XXX: check to see if this has been ACK'd already!
	m := a.priq.Pop()
	a.Unlock()
	if m == nil {
		panic("We've done something wrong here...")
	}
	a.s.egressQueueLock.Lock()
	a.s.egressQueue.Push(m.Value.(*MessageRef))
	a.s.egressQueueLock.Unlock()
}

func (a *ARQ) tworker() {
	for {
		var t <-chan time.Time
		a.Lock()
		if m := a.priq.Peek(); m != nil {
			t = time.After(m.Value.(*MessageRef).timeLeft())
		}
		a.Unlock()
		select {
		case <-a.s.HaltCh():
			a.s.log.Debugf("Terminating gracefully")
			return
		case <-t:
			a.reschedule()
		case <-a.wakeupCh():
		}
	}
}
