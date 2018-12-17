package session

import (
	"github.com/stretchr/testify/assert"
	"io"
	"sync"
	"testing"
	"time"
	//"github.com/stretchr/testify/assert"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
)

func TestNewARQ(t *testing.T) {
	assert := assert.New(t)

	s := &Session{}

	logBackend, err := log.New("", "DEBUG", false)
	assert.NoError(err)
	s.log = logBackend.GetLogger("arq_test")

	q := new(Queue)
	s.egressQueue = q
	s.egressQueueLock = new(sync.Mutex)

	a := NewARQ(s)
	for i := 0; i < 10; i++ {
		m := &MessageRef{}
		m.ID = new([16]byte)

		m.SentAt = time.Now()
		m.ReplyETA = 100 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		a.Enqueue(m)
		time.Sleep(1 * time.Millisecond)
	}
	a.s.log.Debugf("Sent 10 messages")
	time.Sleep(2 * time.Second)

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
	assert.Equal(j, 10)
	s.egressQueueLock.Unlock()

	for i := 0; i < 10; i++ {
		m := &MessageRef{}
		m.ID = new([16]byte)

		m.SentAt = time.Now()
		m.ReplyETA = 100 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		a.Enqueue(m)
		time.Sleep(20 * time.Millisecond)
		if i%2 == 0 {
			m.Reply = []byte("A")
			//er := a.Remove(m)
			//assert.NoError(er)
		}
		time.Sleep(80 * time.Millisecond)
	}
	a.s.log.Debugf("Sent 10 messages")
	time.Sleep(2 * time.Second)

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
	assert.Equal(j, 5)
	a.s.log.Debugf("egressQueue.len: %d", q.len)
	s.egressQueueLock.Unlock()

	a.s.log.Debugf("Halt()")
	a.s.Halt()
}
