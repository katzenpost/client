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

	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/stretchr/testify/assert"
)

func TestNewARQ(t *testing.T) {
	assert := assert.New(t)

	s := &Session{}

	logBackend, err := log.New("", "DEBUG", false)
	assert.NoError(err)
	s.log = logBackend.GetLogger("arq_test")

	// create an egressQueue for rescheduled messages
	q := new(Queue)
	s.egressQueue = q
	s.egressQueueLock = new(sync.Mutex)

	a := NewARQ(s)
	a.s.Halt()
}

func TestARQEnqueue(t *testing.T) {
	assert := assert.New(t)

	s := &Session{}

	logBackend, err := log.New("", "DEBUG", false)
	assert.NoError(err)
	s.log = logBackend.GetLogger("arq_test")

	// create an egressQueue for rescheduled messages
	q := new(Queue)
	s.egressQueue = q
	s.egressQueueLock = new(sync.Mutex)

	a := NewARQ(s)

	// enqueue 10 messages
	for i := 0; i < 10; i++ {
		m := &Message{}
		m.ID = new([16]byte)

		m.SentAt = time.Now()
		m.ReplyETA = 200 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		a.Enqueue(m)
		<-time.After(1 * time.Millisecond)
	}
	a.s.log.Debugf("Sent 10 messages")

	// wait for all of the timers to expire and each message to be enqueued in egressQueue
	<-time.After(1 * time.Second)

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

	// Verify that all messages were placed into egressQueue
	assert.Equal(10, j)
	s.egressQueueLock.Unlock()
	a.s.Halt()
}

func TestARQRemove(t *testing.T) {
	assert := assert.New(t)

	s := &Session{}

	logBackend, err := log.New("", "DEBUG", false)
	assert.NoError(err)
	s.log = logBackend.GetLogger("arq_test")

	// create an egressQueue for rescheduled messages
	q := new(Queue)
	s.egressQueue = q
	s.egressQueueLock = new(sync.Mutex)

	a := NewARQ(s)

	// enqueue 10 messages, and call ARQ.Remove() on half of them before their timers expire
	for i := 0; i < 10; i++ {
		m := &Message{}
		m.ID = new([16]byte)

		m.SentAt = time.Now()
		m.ReplyETA = 100 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		a.Enqueue(m)
		<-time.After(20 * time.Millisecond)
		if i%2 == 0 {
			m.Reply = []byte("A")
			er := a.Remove(m)
			assert.NoError(er)
		}
		<-time.After(80 * time.Millisecond)
	}
	a.s.log.Debugf("Sent 10 messages")
	<-time.After(2 * time.Second)

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
	a.s.log.Debugf("Popped %d messages", j)

	// verify that half of the messages were sent to egressQueue
	assert.Equal(5, j)
	a.s.log.Debugf("egressQueue.len: %d", q.len)
	s.egressQueueLock.Unlock()
	a.s.Halt()
}
