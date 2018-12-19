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
	clog "github.com/katzenpost/core/log"
	"github.com/katzenpost/core/queue"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/assert"
	"gopkg.in/op/go-logging.v1"
)

func NewTestARQ(s *Session) (*ARQ, clockwork.FakeClock) {
	log := logging.MustGetLogger("arq_test")
	fakeClock := clockwork.NewFakeClock()
	a := &ARQ{
		s:     s,
		queue: queue.New(),
		clock: fakeClock,
		log:   log,
	}
	a.L = new(sync.Mutex)
	a.Go(a.worker)
	return a, fakeClock
}

func TestNewARQ(t *testing.T) {
	assert := assert.New(t)

	s := &Session{}

	logBackend, err := clog.New("", "DEBUG", false)
	assert.NoError(err)
	s.log = logBackend.GetLogger("arq_test")

	s.egressQueue = new(Queue)
	s.egressQueueLock = new(sync.Mutex)
	log := logging.MustGetLogger("arq_test")

	a := NewARQ(s, log)
	clock := a.clock
	for i := 0; i < 10; i++ {
		surbId := [sConstants.SURBIDLength]byte{}
		io.ReadFull(rand.Reader, surbId[:])
		m := &MessageRef{
			SURBID: &surbId,
		}
		m.ID = new([16]byte)

		m.SentAt = clock.Now()
		m.ReplyETA = 200 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		a.Enqueue(m)
		clock.Sleep(200 * time.Millisecond)
	}
	a.s.log.Debugf("Sent 10 messages")
	clock.Sleep(1 * time.Second)

	s.egressQueueLock.Lock()
	a.s.log.Debugf("egressQueue.len: %d", s.egressQueue.Len())
	j := 0
	for {
		_, err := s.egressQueue.Pop()
		if err == ErrQueueEmpty {
			break
		}
		j++
	}
	a.s.log.Debugf("Pop() %d messages", j)
	a.s.log.Debugf("egressQueue.len: %d", s.egressQueue.Len())

	assert.Equal(10, j)
	s.egressQueueLock.Unlock()

	for i := 0; i < 10; i++ {
		surbId := [sConstants.SURBIDLength]byte{}
		io.ReadFull(rand.Reader, surbId[:])
		m := &MessageRef{
			SURBID: &surbId,
		}
		m.ID = new([16]byte)

		m.SentAt = clock.Now()
		m.ReplyETA = 100 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		a.Enqueue(m)
		clock.Sleep(20 * time.Millisecond)
		if i%2 == 0 {
			m.Reply = []byte("A")
			a.Remove(*m.SURBID)
		}
		clock.Sleep(80 * time.Millisecond)
	}
	a.s.log.Debugf("Sent 10 messages")
	clock.Sleep(2 * time.Second)

	s.egressQueueLock.Lock()
	a.s.log.Debugf("egressQueue.len: %d", s.egressQueue.Len())
	j = 0
	for {
		_, err := s.egressQueue.Pop()
		if err == ErrQueueEmpty {
			break
		}
		j++
	}
	a.s.log.Debugf("Popped %d messages", j)

	assert.Equal(5, j)
	a.s.log.Debugf("egressQueue.len: %d", s.egressQueue.Len())
	s.egressQueueLock.Unlock()

	a.s.log.Debugf("Halt()")
	a.s.Halt()
}
