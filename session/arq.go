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
	"fmt"
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
	a.s.log.Debugf("Enqueue msg[%x]", m.ID)
	a.Lock()
	a.priq.Enqueue(m.expiry(), m)
	a.Unlock()
	a.Broadcast()
}

// NewARQ intantiates a new ARQ and starts the worker routine
func NewARQ(s *Session) *ARQ {
	a := &ARQ{s: s, priq: queue.New()}
	a.L = new(sync.Mutex)
	a.Go(a.worker)
	return a
}

// Remove removes a MessageRef from the ARQ
func (a *ARQ) Remove(m *MessageRef) error {
	a.Lock()
	defer a.Unlock()
	// If the item to be removed is the first element, stop the timer and schedule a new one.
	if mo := a.priq.Peek(); mo != nil {
		a.s.log.Debugf("Removing message")
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
			return fmt.Errorf("Failed to remove %v", m)
		}
	}
	return nil
}

func (a *ARQ) wakeupCh() chan struct{} {
	a.s.log.Debug("wakeupCh()")
	c := make(chan struct{})
	go func() {
		defer close(c)
		a.L.Lock()
		a.Wait()
		a.s.log.Debug("wakeup")
		a.L.Unlock()
	}()
	return c
}

func (a *ARQ) reschedule() {
	a.s.log.Debugf("Timer fired at %s", time.Now())
	a.Lock()
	m := a.priq.Pop()
	a.Unlock()
	if m == nil {
		panic("We've done something wrong here...")
	}
	// XXX should lock m
	if len(m.Value.(*MessageRef).Reply) > 0 {
		// Already ACK'd
		return
	}
	a.s.log.Debugf("Rescheduling msg[%x]", m.Value.(*MessageRef).ID)
	a.s.egressQueueLock.Lock()
	err := a.s.egressQueue.Push(m.Value.(*MessageRef))
	a.s.egressQueueLock.Unlock()
	if err != nil {
		panic(err)
	}
}

func (a *ARQ) worker() {
	for {
		a.s.log.Debugf("Loop0")
		var c <-chan time.Time
		a.Lock()
		if m := a.priq.Peek(); m != nil {
			msg := m.Value.(*MessageRef)
			tl := msg.timeLeft()
			if tl < 0 {
				a.s.log.Debugf("Queue behind schedule %v", tl)
				a.Unlock()
				a.reschedule()
				continue
			} else {
				a.s.log.Debugf("Setting timer for msg[%x]: %d", msg.ID, tl)
				a.timer = time.NewTimer(tl)
				c = a.timer.C
			}
		} else {
			a.s.log.Debug("Nothing in priq")
		}
		a.Unlock()
		select {
		case <-a.s.HaltCh():
			a.timer.Stop()
			a.s.log.Debugf("Terminating gracefully")
			return
		case <-c:
			a.reschedule()
		case <-a.wakeupCh():
			a.s.log.Debugf("Woke")
			a.timer.Stop() // Enqueue may add item with higher priority than current timer
		}
	}
}
