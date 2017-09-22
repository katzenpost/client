// fragmentation.go - message fragmentation and reassembly
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
	"bytes"
	"errors"
	"io"
	"math"
	"sort"

	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/crypto/block"
	"github.com/katzenpost/client/storage"
)

// deduplicateBlocks deduplicates the given blocks according to the BlockIDs
func deduplicateBlocks(ingressBlocks []*storage.IngressBlock) []*storage.IngressBlock {
	blockIDMap := make(map[uint16]bool)
	deduped := []*storage.IngressBlock{}
	for _, b := range ingressBlocks {
		_, ok := blockIDMap[b.Block.BlockID]
		if !ok {
			blockIDMap[b.Block.BlockID] = true
			deduped = append(deduped, b)
		}
	}
	return deduped
}

// validBlocks returns true if the given blocks are valid
// according to "Panoramix Mix Network End-to-end Protocol Specification"
// section 4.2.1 Client Message Processing:
//      When reassembling messages, the values of `s`, message_id, and
//      total_blocks are fixed for any given distinct message. All
//      differences in those fields across Blocks MUST be interpreted as
//      the Blocks belonging to different messages.
func validBlocks(ingressBlocks []*storage.IngressBlock) bool {
	messageID := ingressBlocks[0].Block.MessageID
	s := ingressBlocks[0].S
	totalBlocks := ingressBlocks[0].Block.TotalBlocks
	for _, b := range ingressBlocks {
		if !bytes.Equal(messageID[:], b.Block.MessageID[:]) {
			return false
		}
		if !bytes.Equal(s[:], b.S[:]) {
			return false
		}
		if totalBlocks != b.Block.TotalBlocks {
			return false
		}
	}
	return true
}

// ByBlockID implements sort.Interface for []*block.Block
type ByBlockID []*storage.IngressBlock

func (a ByBlockID) Len() int           { return len(a) }
func (a ByBlockID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByBlockID) Less(i, j int) bool { return a[i].Block.BlockID < a[j].Block.BlockID }

// reassembleMessage reassembles a message returns it or an error
// if a block is missing
func reassembleMessage(ingressBlocks []*storage.IngressBlock) ([]byte, error) {
	sort.Sort(ByBlockID(ingressBlocks))
	message := []byte{}
	for i, b := range ingressBlocks {
		if ingressBlocks[i].Block.BlockID != uint16(i) {
			return nil, errors.New("message reassembler failed: missing message block")
		}
		message = append(message, b.Block.Block...)
	}
	return message, nil
}

// fragmentMessage fragments a message into a slice of blocks
func fragmentMessage(randomReader io.Reader, message []byte) ([]*block.Block, error) {
	blocks := []*block.Block{}
	if len(message) <= block.BlockLength {
		id := [constants.MessageIDLength]byte{}
		_, err := randomReader.Read(id[:])
		if err != nil {
			return nil, err
		}
		payload := [block.BlockLength]byte{}
		copy(payload[:], message)
		block := block.Block{
			MessageID:   id,
			TotalBlocks: 1,
			BlockID:     0,
			Block:       payload[:],
		}
		blocks = append(blocks, &block)
	} else {
		totalBlocks := int(math.Ceil(float64(len(message)) / float64(block.BlockLength)))
		id := [constants.MessageIDLength]byte{}
		_, err := randomReader.Read(id[:])
		if err != nil {
			return nil, err
		}
		for i := 0; i < totalBlocks; i++ {
			var blockPayload []byte
			if i == totalBlocks-1 {
				payload := [block.BlockLength]byte{}
				blockPayload = payload[:]
				copy(blockPayload[:], message[i*block.BlockLength:])
			} else {
				blockPayload = message[i*block.BlockLength : (i+1)*block.BlockLength]
			}
			block := block.Block{
				MessageID:   id,
				TotalBlocks: uint16(totalBlocks),
				BlockID:     uint16(i),
				Block:       blockPayload,
			}
			blocks = append(blocks, &block)
		}
	}
	return blocks, nil
}
