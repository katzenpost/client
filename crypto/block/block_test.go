// block_test.go - End to end encrypted/authenticated block tests.
// Copyright (C) 2017  David Anthony Stainton, Yawning Angel
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

package block

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx"
	"github.com/stretchr/testify/require"
)

func TestBlock(t *testing.T) {
	require := require.New(t)

	const (
		hdrLength = constants.SphinxPlaintextHeaderLength + sphinx.SURBLength
	)

	idKeyAlice, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "Block: Alice NewKeypair()")
	hAlice := NewHandler(idKeyAlice, rand.Reader)

	idKeyBob, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "Block: Bob NewKeypair()")
	hBob := NewHandler(idKeyBob, rand.Reader)

	// Generate a payload and the template block.
	payload := make([]byte, BlockLength)
	_, err = io.ReadFull(rand.Reader, payload)
	require.NoError(err, "Block: Generating Payload")
	blkA := &Block{
		TotalBlocks: 0xa5a5,
		BlockID:     0x5a5a,
	}
	_, err = io.ReadFull(rand.Reader, blkA.MessageID[:])
	require.NoError(err, "Block: Generating Message ID")

	testSize := func(sz int) {
		// Encrypt.
		blkA.Block = payload[:sz]
		ct, err := hAlice.Encrypt(idKeyBob.PublicKey(), blkA)
		require.NoError(err, "Block encrypt failure")
		require.Equal(len(ct), constants.ForwardPayloadLength-hdrLength)

		// Decrypt.
		blk, peerPk, err := hBob.Decrypt(ct)
		require.NoErrorf(err, "Block: Decrypt() (%d bytes)", sz)
		require.Equal(blkA, blk, "Block: payload mismatch (%d bytes)", sz)
		require.Equal(idKeyAlice.PublicKey(), peerPk, "Block: peerPk mismatch (%d bytes)", sz)
	}

	testSize(len(payload))
	testSize(23)
}
