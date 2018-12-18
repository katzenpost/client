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
	"io"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/queue"
	"github.com/stretchr/testify/assert"
)

func NewTestARQ(s *Session) (*ARQ, clockwork.FakeClock) {
	fakeClock := clockwork.NewFakeClock()
	a := &ARQ{
		s:     s,
		priq:  queue.New(),
		clock: fakeClock,
	}
	a.L = new(sync.Mutex)
	a.Go(a.worker)
	return a, fakeClock
}

func TestNewARQ(t *testing.T) {
	assert := assert.New(t)

	s := &Session{}

	logBackend, err := log.New("", "DEBUG", false)
	assert.NoError(err)
	s.log = logBackend.GetLogger("arq_test")

	q := new(Queue)
	s.egressQueue = q
	s.egressQueueLock = new(sync.Mutex)

	a, fakeClock := NewTestARQ(s)
	for i := 0; i < 10; i++ {
		m := &MessageRef{}
		m.ID = new([16]byte)

		m.SentAt = fakeClock.Now()
		m.ReplyETA = 200 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		a.Enqueue(m)
		fakeClock.Advance(1 * time.Millisecond)
	}
	a.s.log.Debugf("Sent 10 messages")

	fakeClock.Advance(1 * time.Second)

	s.egressQueueLock.Lock()
	a.s.log.Debugf("egressQueue.len: %d", q.len)
	j := 0
	for {
		_, err := s.egressQueue.Pop()
		if err == ErrQueueEmpty {
			break
		}
		j++
	}
	a.s.log.Debugf("Pop() %d messages", j)
	a.s.log.Debugf("egressQueue.len: %d", q.len)

	//assert.Equal(10, j)
	s.egressQueueLock.Unlock()

	for i := 0; i < 10; i++ {
		m := &MessageRef{}
		m.ID = new([16]byte)

		m.SentAt = fakeClock.Now()
		m.ReplyETA = 100 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		a.Enqueue(m)
		fakeClock.Advance(20 * time.Millisecond)
		if i%2 == 0 {
			m.Reply = []byte("A")
			//er := a.Remove(m)
			//assert.NoError(er)
		}
		fakeClock.Advance(80 * time.Millisecond)
	}
	a.s.log.Debugf("Sent 10 messages")
	fakeClock.Advance(2 * time.Second)

	s.egressQueueLock.Lock()
	a.s.log.Debugf("egressQueue.len: %d", q.len)
	j = 0
	for {
		_, err := s.egressQueue.Pop()
		if err == ErrQueueEmpty {
			break
		}
		j++
	}
	a.s.log.Debugf("Popped %d messages", j)

	//assert.Equal(5, j)
	a.s.log.Debugf("egressQueue.len: %d", q.len)
	s.egressQueueLock.Unlock()

	a.s.log.Debugf("Halt()")
	a.s.Halt()
}
