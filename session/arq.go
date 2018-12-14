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

	priq  *queue.PriorityQueue
	s     *Session
	timer *time.Timer
}

func (m *MessageRef) expiry() uint64 {
	// TODO: add exponential backoff
	return uint64(m.SentAt.Add(m.ReplyETA).UnixNano())
}

func (m *MessageRef) timeLeft() time.Duration {
	return m.SentAt.Add(m.ReplyETA).Sub(time.Now())
}

// Enqueue adds a message to the ARQ
func (a *ARQ) Enqueue(m *MessageRef) {
	a.Lock()
	defer a.Unlock()
	a.priq.Enqueue(m.expiry(), m)
	if a.priq.Len() == 1 {
		a.Broadcast()
	}
}

// NewARQ intantiates a new ARQ and starts the worker routine
func NewARQ(s *Session) *ARQ {
	a := &ARQ{s: s, priq: queue.New()}
	a.Go(a.worker)
	return a
}

// Remove removes a MessageRef from the ARQ
func (a *ARQ) Remove(m *MessageRef) {
	a.Lock()
	defer a.Unlock()
	// If the item to be removed is the first element, stop the timer and schedule a new one.
	if mo := a.priq.Peek(); mo != nil {
		if mo.Value.(*MessageRef) == m {
			a.timer.Stop()
			a.priq.Pop()
			if a.priq.Len() > 0 {
				a.Broadcast()
			}
		}
	} else {
		mo := a.priq.Remove(m.expiry())
		switch mo {
		case m:
		case nil:
			a.s.log.Debugf("Failed to remove %v from queue, already gone", m)
		default:
			a.s.log.Errorf("Removed wrong item from queue! Re-enqueuing")
			defer a.Enqueue(mo.(*MessageRef))
		}
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
	m := a.priq.Pop()
	a.Unlock()
	if m == nil {
		panic("We've done something wrong here...")
	}
	a.s.egressQueueLock.Lock()
	a.s.egressQueue.Push(m.Value.(*MessageRef))
	a.s.egressQueueLock.Unlock()
}

func (a *ARQ) worker() {
	for {
		a.Lock()
		if m := a.priq.Peek(); m != nil {
			a.timer = time.NewTimer(m.Value.(*MessageRef).timeLeft())
		}
		a.Unlock()
		select {
		case <-a.s.HaltCh():
			a.timer.Stop()
			a.s.log.Debugf("Terminating gracefully")
			return
		case <-a.timer.C:
			a.reschedule()
		case <-a.wakeupCh():
		}
	}
}
