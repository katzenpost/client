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

	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/crypto/block"
	"github.com/katzenpost/client/storage"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
)

func TestIngressBlockValidation(t *testing.T) {
	require := require.New(t)

	staticKey := [32]byte{}
	messageID := [constants.MessageIDLength]byte{}
	blocks := []*storage.IngressBlock{
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				MessageID: messageID,
				BlockID:   0,
				Block:     []byte{1, 2, 3},
			},
		},
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				MessageID: messageID,
				BlockID:   2,
				Block:     []byte{7, 8, 9},
			},
		},
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				MessageID: messageID,
				BlockID:   1,
				Block:     []byte{4, 5, 6},
			},
		},
	}
	isValid := validBlocks(blocks)
	require.True(isValid, "expected to be true")
}

func TestIngressBlockValidationFail1(t *testing.T) {
	require := require.New(t)

	staticKey := [32]byte{}
	messageID1 := [constants.MessageIDLength]byte{}
	messageID2 := [constants.MessageIDLength]byte{}
	_, err := rand.Reader.Read(messageID2[:])
	require.NoError(err, "rand reader failed")
	blocks := []*storage.IngressBlock{
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				MessageID: messageID1,
				BlockID:   0,
				Block:     []byte{1, 2, 3},
			},
		},
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				MessageID: messageID2,
				BlockID:   2,
				Block:     []byte{7, 8, 9},
			},
		},
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				MessageID: messageID1,
				BlockID:   1,
				Block:     []byte{4, 5, 6},
			},
		},
	}
	isValid := validBlocks(blocks)
	require.False(isValid, "validBlocks should've failed")
}

func TestIngressBlockValidationFail2(t *testing.T) {
	require := require.New(t)

	staticKey1 := [32]byte{}
	staticKey2 := [32]byte{}
	_, err := rand.Reader.Read(staticKey2[:])
	require.NoError(err, "rand reader failed")
	messageID1 := [constants.MessageIDLength]byte{}
	blocks := []*storage.IngressBlock{
		&storage.IngressBlock{
			S: staticKey1,
			Block: &block.Block{
				MessageID: messageID1,
				BlockID:   0,
				Block:     []byte{1, 2, 3},
			},
		},
		&storage.IngressBlock{
			S: staticKey2,
			Block: &block.Block{
				MessageID: messageID1,
				BlockID:   2,
				Block:     []byte{7, 8, 9},
			},
		},
		&storage.IngressBlock{
			S: staticKey1,
			Block: &block.Block{
				MessageID: messageID1,
				BlockID:   1,
				Block:     []byte{4, 5, 6},
			},
		},
	}
	isValid := validBlocks(blocks)
	require.False(isValid, "validBlocks should've failed")
}

func TestIngressBlockValidationFail3(t *testing.T) {
	require := require.New(t)

	staticKey1 := [32]byte{}
	messageID1 := [constants.MessageIDLength]byte{}
	blocks := []*storage.IngressBlock{
		&storage.IngressBlock{
			S: staticKey1,
			Block: &block.Block{
				TotalBlocks: 3,
				MessageID:   messageID1,
				BlockID:     0,
				Block:       []byte{1, 2, 3},
			},
		},
		&storage.IngressBlock{
			S: staticKey1,
			Block: &block.Block{
				TotalBlocks: 3,
				MessageID:   messageID1,
				BlockID:     2,
				Block:       []byte{7, 8, 9},
			},
		},
		&storage.IngressBlock{
			S: staticKey1,
			Block: &block.Block{
				TotalBlocks: 1,
				MessageID:   messageID1,
				BlockID:     1,
				Block:       []byte{4, 5, 6},
			},
		},
	}
	isValid := validBlocks(blocks)
	require.False(isValid, "validBlocks should've failed")
}

func TestDeduplication(t *testing.T) {
	require := require.New(t)

	staticKey := [32]byte{}
	blocks := []*storage.IngressBlock{
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				BlockID: 0,
				Block:   []byte{1, 2, 3},
			},
		},
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				BlockID: 0,
				Block:   []byte{1, 2, 3},
			},
		},
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				BlockID: 1,
				Block:   []byte{4, 5, 6},
			},
		},
	}
	deduped := deduplicateBlocks(blocks)
	require.NotEqual(len(deduped), len(blocks), "deduplicateBlocks failed")
	for _, d := range deduped {
		t.Logf("deduped id %d", d.Block.BlockID)
	}
}

func TestFragmentationBig(t *testing.T) {
	require := require.New(t)

	message := [block.BlockLength*2 + 77]byte{}
	_, err := rand.Reader.Read(message[:])
	require.NoError(err, "rand reader failed")

	blocks, err := fragmentMessage(rand.Reader, message[:])
	require.NoError(err, "fragmentMessage failed")

	require.Equal(3, len(blocks), "wrong number of blocks")
	for _, b := range blocks {
		require.Equal(block.BlockLength, len(b.Block), "block is incorrect size")
	}
}

func TestFragmentationSmall(t *testing.T) {
	require := require.New(t)

	message := [block.BlockLength - 22]byte{}
	_, err := rand.Reader.Read(message[:])
	require.NoError(err, "rand reader failed")

	blocks, err := fragmentMessage(rand.Reader, message[:])
	require.NoError(err, "fragmentMessage failed")

	require.Equal(1, len(blocks), "wrong number of blocks")
	require.Equal(block.BlockLength, len(blocks[0].Block), "block is incorrect size")
}

func TestReassembly(t *testing.T) {
	require := require.New(t)

	staticKey := [32]byte{}
	blocks := []*storage.IngressBlock{
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				BlockID: 2,
				Block:   []byte{7, 8, 9},
			},
		},
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				BlockID: 0,
				Block:   []byte{1, 2, 3},
			},
		},
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				BlockID: 1,
				Block:   []byte{4, 5, 6},
			},
		},
	}
	message, err := reassembleMessage(blocks)
	require.NoError(err, "reassembleMessage failed")
	t.Logf("message is %v", message)
}

func TestReassemblyMissingBlock(t *testing.T) {
	require := require.New(t)

	staticKey := [32]byte{}
	blocks := []*storage.IngressBlock{
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				BlockID: 2,
				Block:   []byte{7, 8, 9},
			},
		},
		&storage.IngressBlock{
			S: staticKey,
			Block: &block.Block{
				BlockID: 0,
				Block:   []byte{1, 2, 3},
			},
		},
	}
	_, err := reassembleMessage(blocks)
	require.Error(err, "reassembleMessage should've failed")
}
