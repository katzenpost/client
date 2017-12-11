// db_test.go - db tests
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

package storage

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/katzenpost/client/crypto/block"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/require"
)

func TestSerialization(t *testing.T) {
	require := require.New(t)

	b := block.Block{
		TotalBlocks: uint16(1),
		BlockID:     uint16(1),
		Block:       []byte(`"The time has come," the Walrus said`),
	}
	s := EgressBlock{
		SenderProvider:    "acme.com",
		RecipientProvider: "nsa.gov",
		Block:             b,
	}
	_, err := rand.Reader.Read(s.SURBID[:])
	require.NoError(err, "wtf")
	_, err = rand.Reader.Read(s.SURBKeys)
	require.NoError(err, "wtf")

	rawEgressBlock, err := b.ToBytes()
	require.NoError(err, "wtf")

	t.Logf("rawEgressBlock is %x", rawEgressBlock)

	egressBlock, err := EgressBlockFromBytes(rawEgressBlock)
	require.NoError(err, "wtf")

	t.Logf("SURBID %x SURBKeys %x", egressBlock.SURBID, egressBlock.SURBKeys)
}

func TestDBBasics(t *testing.T) {
	require := require.New(t)

	dbFile, err := ioutil.TempFile("", "db_test1")
	require.NoError(err, "unexpected TempFile error")
	defer func() {
		err := os.Remove(dbFile.Name())
		require.NoError(err, "unexpected os.Remove error")
	}()
	store, err := New(dbFile.Name())
	require.NoError(err, "unexpected New() error")

	rid := []byte{1, 2, 3, 4}
	recipientID := [constants.RecipientIDLength]byte{}
	copy(recipientID[:], rid)
	b := block.Block{
		TotalBlocks: uint16(1),
		BlockID:     uint16(1),
		Block:       []byte(`"The time has come," the Walrus said`),
	}
	id := []byte{1, 2, 3, 4, 5, 6}
	s := EgressBlock{
		SenderProvider:    "acme.com",
		RecipientProvider: "nsa.gov",
		RecipientID:       recipientID,
		Block:             b,
	}
	copy(s.SURBID[:], id)

	_, err = store.PutEgressBlock(&s)
	require.NoError(err, "unexpected storeMessage() error")

	surbs, err := store.GetKeys()
	require.NoError(err, "unexpected GetKeys() error")

	for _, surb := range surbs {
		message, err := store.Get(&surb)
		require.NoError(err, "unexpected Get error")
		t.Log(string(message))
	}

	err = store.Remove(&surbs[0])
	require.NoError(err, "unexpected Remove() error")

	surbs, err = store.GetKeys()
	require.NoError(err, "unexpected GetKeys() error")

	require.Equal(len(surbs), 0, "expected zero length")

	err = store.Close()
	require.NoError(err, "unexpected Close() error")
}
