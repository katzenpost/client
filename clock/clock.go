// clock.go - Katzenpost epoch time type for clients.
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

// Package clock
package clock

import (
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/katzenpost/core/epochtime"
)

type Clock struct {
	c clockwork.Clock
}

func New(c clockwork.Clock) *Clock {
	return &Clock{c}
}

// Now returns the current Katzenpost epoch, time since the start of the
// current, and time till the next epoch.
func (c *Clock) Now() (current uint64, elapsed, till time.Duration) {
	// Cache now for a consistent value for this query.
	now := c.c.Now()

	fromEpoch := c.c.Since(epochtime.Epoch)
	if fromEpoch < 0 {
		panic("clock: BUG: system time appears to predate the epoch")
	}

	current = uint64(fromEpoch / epochtime.Period)

	base := epochtime.Epoch.Add(time.Duration(current) * epochtime.Period)
	elapsed = now.Sub(base)
	till = base.Add(epochtime.Period).Sub(now)
	return
}
