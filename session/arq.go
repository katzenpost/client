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
	"bytes"
	"sync"
	"time"

	"github.com/katzenpost/core/queue"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/worker"
)

// ARQ is the struct type that keeps state for reliable message delivery
type ARQ struct {
	sync.Mutex
	sync.Cond
	worker.Worker

	priq   *queue.PriorityQueue
	s      *Session
	timer  *time.Timer
	wakech chan struct{}
}

// NewARQ intantiates a new ARQ and starts the worker routine
func NewARQ(s *Session) *ARQ {
	a := &ARQ{s: s, priq: queue.New()}
	a.L = new(sync.Mutex)
	a.Go(a.worker)
	return a
}

// Enqueue adds a message to the ARQ
func (a *ARQ) Enqueue(m *MessageRef) {
	a.s.log.Debugf("Enqueue msg[%x]", m.ID)
	a.Lock()
	a.priq.Enqueue(m.expiry(), m)
	a.Unlock()
	a.Signal()
}

func (a *ARQ) Remove(surbID [sConstants.SURBIDLength]byte) {
	filter := func(value interface{}) bool {
		v := value.(MessageRef)
		return bytes.Equal(v.SURBID[:], surbID[:])
	}
	a.priq.FilterOnce(filter)
}

func (a *ARQ) wakeupCh() chan struct{} {
	a.s.log.Debug("wakeupCh()")
	if a.wakech != nil {
		return a.wakech
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
	a.wakech = c
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
