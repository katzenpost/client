// test_fragmentation.go - test message fragmentation
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

// Package proxy provides mixnet client proxies
package proxy

import (
	"testing"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
)

func TestFragmentation(t *testing.T) {
	require := require.New(t)

	message := [constants.ForwardPayloadLength*2 + 77]byte{}
	_, err := rand.Reader.Read(message[:])
	require.NoError(err, "rand reader failed")

	blocks, err := fragmentMessage(rand.Reader, message[:])
	require.NoError(err, "fragmentMessage failed")

	require.Equal(3, len(blocks), "wrong number of blocks")
	for _, block := range blocks {
		require.Equal(constants.ForwardPayloadLength, len(block.Block), "block is incorrect size")
	}
}
