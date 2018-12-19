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
	"bytes"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/katzenpost/core/queue"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/worker"
)

// ARQ is the struct type that keeps state for reliable message delivery.
type ARQ struct {
	sync.Mutex
	sync.Cond
	worker.Worker

	queue *queue.PriorityQueue
	s     *Session

	wakeChan   chan struct{}
	removeChan chan [sConstants.SURBIDLength]byte

	clock clockwork.Clock
}

// NewARQ makes a new ARQ and starts the worker thread.
func NewARQ(s *Session) *ARQ {
	a := &ARQ{
		s:          s,
		queue:      queue.New(),
		clock:      clockwork.NewRealClock(),
		removeChan: make(chan [sConstants.SURBIDLength]byte),
	}
	a.L = new(sync.Mutex)
	a.Go(a.worker)
	return a
}

// Enqueue adds a message to the ARQ
func (a *ARQ) Enqueue(m *MessageRef) {
	a.s.log.Debugf("Enqueue msg[%x]", m.ID)
	a.Lock()
	a.queue.Enqueue(m.expiry(), m)
	a.Unlock()
	a.Signal()
}

// Remove removes the item with the given SURB ID.
func (a *ARQ) Remove(surbID [sConstants.SURBIDLength]byte) {
	a.removeChan <- surbID
}

func (a *ARQ) remove(surbID [sConstants.SURBIDLength]byte) {
	filter := func(value interface{}) bool {
		v := value.(MessageRef)
		return bytes.Equal(v.SURBID[:], surbID[:])
	}
	a.Lock()
	a.queue.FilterOnce(filter)
	a.Unlock()
}

func (a *ARQ) wakeupCh() chan struct{} {
	a.s.log.Debug("wakeupCh()")
	if a.wakeChan != nil {
		return a.wakeChan
	}
	c := make(chan struct{})
	go func() {
		defer close(c)
		var v struct{}
		for {
			a.L.Lock()
			a.Wait()
			a.L.Unlock()
			select {
			case <-a.HaltCh():
				a.s.log.Debugf("CondCh worker() returning")
				return
			case c <- v:
				a.s.log.Debugf("CondCh worker() writing")
			}
		}
	}()
	a.wakeChan = c
	return c
}

func (a *ARQ) pop() *MessageRef {
	m := a.queue.Pop()
	return m.Value.(*MessageRef)
}

func (a *ARQ) pushEgress(mesgRef *MessageRef) {
	// XXX should lock m
	if len(mesgRef.Reply) > 0 {
		// Already ACK'd
		return
	}
	a.s.log.Debugf("Rescheduling msg[%x]", mesgRef.ID)
	a.s.egressQueueLock.Lock()
	err := a.s.egressQueue.Push(mesgRef)
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
		if m := a.queue.Peek(); m != nil {
			msg := m.Value.(*MessageRef)
			tl := msg.timeLeft(a.clock)
			if tl < 0 {
				a.s.log.Debugf("Queue behind schedule %v", tl)
				mesgRef := a.pop()
				a.Unlock()
				a.pushEgress(mesgRef)
				continue
			} else {
				a.s.log.Debugf("Setting timer for msg[%x]: %d", msg.ID, tl)
				c = a.clock.After(tl)
			}
		} else {
			a.s.log.Debug("Nothing in queue")
		}
		a.Unlock()
		select {
		case <-a.s.HaltCh():
			a.s.log.Debugf("Terminating gracefully")
			return
		case surbID := <-a.removeChan:
			a.remove(surbID)
			continue
		case <-c:
			a.s.log.Debugf("Timer fired at %s", a.clock.Now())
			a.Lock()
			mesgRef := a.pop()
			a.Unlock()
			a.pushEgress(mesgRef)
		case <-a.wakeupCh():
			a.s.log.Debugf("Woke")
		}
	}
}
