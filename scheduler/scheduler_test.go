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
)

func TestScheduler(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)

	handler := func(payload []byte) {
		t.Logf("handler: payload len %d\n", len(payload))
		wg.Done()
	}

	s := New(handler)

	payload1 := []byte{1, 2, 3, 4}
	s.Schedule(time.Second*30, payload1)

	payload2 := []byte{2, 4, 5}
	s.Schedule(time.Second*3, payload2)

	wg.Wait()
}
