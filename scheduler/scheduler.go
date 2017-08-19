// scheduler.go - mixnet client scheduler
// Copyright (C) 2017  David Stainton.
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

// Package scheduler for scheduling tasks in the future
package scheduler

import (
	"time"

	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/queue"
)

type Scheduler struct {
	queue          *queue.PriorityQueue
	payloadHandler func([]byte)
	timer          *time.Timer
}

func New(payloadHandler func([]byte)) *Scheduler {
	s := Scheduler{
		queue:          queue.New(),
		payloadHandler: payloadHandler,
	}
	return &s
}

func (s *Scheduler) run() {
	entry := s.queue.Pop()
	s.payloadHandler(entry.Value)
}

func (s *Scheduler) Schedule(duration time.Duration, payload []byte) {
	now := monotime.Now()
	priority := now + duration
	s.queue.Enqueue(uint64(priority), payload)
	entry := s.queue.Peek()
	if time.Duration(entry.Priority) <= now {
		_ = s.queue.Pop()
		s.payloadHandler(entry.Value)
	} else {
		if s.timer != nil {
			s.timer.Stop()
		}
		s.timer = time.AfterFunc(time.Duration(entry.Priority)-now, s.run)
	}
}
