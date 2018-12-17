package session

import (
	"testing"
	"time"
	"io"
	"github.com/stretchr/testify/assert"
	"sync"
	//"github.com/stretchr/testify/assert"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/crypto/rand"
)

func TestNewARQ(t *testing.T) {
	assert := assert.New(t)

	s := &Session{}

	logBackend, err := log.New("", "DEBUG", false)
	assert.NoError(err)
	s.log = logBackend.GetLogger("arq_test")

	s.egressQueue = new(Queue)
	s.egressQueueLock = new(sync.Mutex)

	a := NewARQ(s)
	for i := 0; i< 10; i++ {
		m := &MessageRef{}
		m.ID = new([16]byte)

		m.SentAt = time.Now()
		m.ReplyETA = 1000 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		a.Enqueue(m)
	}
	j := 0
	for err, i := s.egressQueue.Pop(); err ==nil && i != nil; j++ {
	}
	assert.Equal(j, 10)

	for i := 0; i< 10; i++ {
		m := &MessageRef{}
		m.ID = new([16]byte)

		m.SentAt = time.Now()
		m.ReplyETA = 1000 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		a.Enqueue(m)
		time.Sleep(20 * time.Millisecond)
		if i %2 == 0 {
			a.Remove(m)
		}
		time.Sleep(80 * time.Millisecond)
	}
	time.Sleep(2000 * time.Millisecond)
	j = 0
	for {
		err, i := s.egressQueue.Pop()
		if err == nil && i != nil {
			j++
		} else {
			break
		}
	}
	assert.Equal(j, 5)

}
