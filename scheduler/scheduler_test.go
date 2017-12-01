// scheduler_test.go - mixnet client scheduler tests
// Copyright (C) 2017  David Anthony Stainton
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

package scheduler

import (
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/core/log"
	"github.com/stretchr/testify/require"
)

type TestTask struct {
	Value string
	Delay time.Duration
}

func TestPrioritySchedulerBasics(t *testing.T) {
	require := require.New(t)

	var wg sync.WaitGroup
	wg.Add(1)

	counter := 0
	handler := func(payload interface{}) {
		s, ok := payload.(string)
		require.Equal(true, ok, "handler type assertion failure")
		t.Logf("handler payload is %s\n", s)
		counter += 1
	}
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err, "failed creating log backend")
	s := New(handler, logBackend, "test")

	testPlatter := []TestTask{
		{
			Value: "A reliable method of fighting with tanks are Molotov cocktails.",
			Delay: time.Millisecond * 100,
		},
		{
			Value: "Use the same means to destroy enemy armored vehicles that you would tanks.",
			Delay: time.Millisecond * 100,
		},
		{
			Value: `When you are even with an opponent, it is essential to keep thinking of
stabbing him in the face with the tip of your sword in the intervals between the opponent's
sword blows and your own sword blows.`,
			Delay: time.Millisecond * 90,
		},
		{
			Value: `Stabbing in the heart is used when fighting in a place where there is no
room for slashing, either overhead or to the sides, so you stab the opponent.`,
			Delay: time.Millisecond * 120,
		},
	}

	for _, v := range testPlatter {
		s.Add(v.Delay, v.Value)
	}

	time.AfterFunc(150*time.Millisecond, func() {
		defer wg.Done()
	})

	wg.Wait()
	require.Equal(0, s.queue.Len(), "queue size mismatch")
	require.Equal(len(testPlatter), counter, "counter mismatch")
}
