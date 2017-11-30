// scheduler.go - mixnet client priority queue backed scheduler
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

package scheduler

import (
	"sync"
	"time"

	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/queue"
)

// PriorityScheduler is a priority queue backed scheduler
type PriorityScheduler struct {
	sync.RWMutex

	queue       *queue.PriorityQueue
	taskHandler func(interface{})
	timer       *time.Timer
}

// New creates a new PriorityScheduler given a taskHandler function
// which is eventually responsible for dealing with the scheduled items
func New(taskHandler func(interface{})) *PriorityScheduler {
	s := PriorityScheduler{
		queue:       queue.New(),
		taskHandler: taskHandler,
	}
	return &s
}

// pop pops an item off the priority queue with a lock
func (s *PriorityScheduler) pop() *queue.Entry {
	s.Lock()
	defer s.Unlock()
	return s.queue.Pop()
}

// run causes the lowest priority task
// to be processed before scheduling
// the handling of the next scheduled task
func (s *PriorityScheduler) run() {
	entry := s.pop()
	s.taskHandler(entry.Value)
	s.schedule()
}

// peek peeks into the priority queue with a read-lock
func (s *PriorityScheduler) peek() *queue.Entry {
	s.RLock()
	defer s.RUnlock()
	return s.queue.Peek()
}

// schedule schedules the handling of the lowest
// priority item. Queue priority is compared to
// current monotime.
func (s *PriorityScheduler) schedule() {
	entry := s.peek()
	if entry == nil {
		return
	}
	s.Lock()
	defer s.Unlock()
	now := monotime.Now()
	if time.Duration(entry.Priority) <= now {
		s.timer = time.AfterFunc(time.Duration(0), s.run)
	} else {
		if s.timer != nil {
			s.timer.Stop()
		}
		s.timer = time.AfterFunc(time.Duration(entry.Priority)-now, s.run)
	}
}

// enqueue adds task to priority queue and uses mutex
func (s *PriorityScheduler) enqueue(priority uint64, task interface{}) {
	s.Lock()
	defer s.Unlock()

	s.queue.Enqueue(uint64(priority), task)
}

// Add adds a task to the scheduler
func (s *PriorityScheduler) Add(duration time.Duration, task interface{}) {
	now := monotime.Now()
	priority := now + duration
	s.enqueue(uint64(priority), task)
	s.schedule()
}

// Shutdown shuts down the scheduler
func (s *PriorityScheduler) Shutdown() {
	s.Lock()
	defer s.Unlock()

	if s.timer != nil {
		if !s.timer.Stop() {
			<-s.timer.C
		}
	}
}
