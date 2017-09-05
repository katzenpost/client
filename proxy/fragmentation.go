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
	"errors"
	"io"
	"math"
	"sort"

	clientconstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/crypto/block"
	"github.com/katzenpost/core/constants"
)

// ByBlockID implements sort.Interface for []*block.Block
type ByBlockID []*block.Block

func (a ByBlockID) Len() int           { return len(a) }
func (a ByBlockID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByBlockID) Less(i, j int) bool { return a[i].BlockID < a[j].BlockID }

// reassembleMessage reassembles a message returns it or an error
// if a block is missing
func reassembleMessage(blocks []*block.Block) ([]byte, error) {
	sort.Sort(ByBlockID(blocks))
	message := []byte{}
	for i, block := range blocks {
		if blocks[i].BlockID != uint16(i) {
			return nil, errors.New("message reassembler failed: missing message block")
		}
		message = append(message, block.Block...)
	}
	return message, nil
}

// fragmentMessage fragments a message into a slice of blocks
func fragmentMessage(randomReader io.Reader, message []byte) ([]*block.Block, error) {
	blocks := []*block.Block{}
	if len(message) <= constants.ForwardPayloadLength {
		id := [clientconstants.MessageIDLength]byte{}
		_, err := randomReader.Read(id[:])
		if err != nil {
			return nil, err
		}
		block := block.Block{
			MessageID:   id,
			TotalBlocks: 1,
			BlockID:     0,
			Block:       message,
		}
		blocks = append(blocks, &block)
	} else {
		totalBlocks := int(math.Ceil(float64(len(message)) / float64(constants.ForwardPayloadLength)))
		id := [clientconstants.MessageIDLength]byte{}
		_, err := randomReader.Read(id[:])
		for i := 0; i < totalBlocks; i++ {
			if err != nil {
				return nil, err
			}
			var blockPayload []byte
			if i == totalBlocks-1 {
				payload := [constants.ForwardPayloadLength]byte{}
				blockPayload = payload[:]
				copy(blockPayload[:], message[i*constants.ForwardPayloadLength:])
			} else {
				blockPayload = message[i*constants.ForwardPayloadLength : (i+1)*constants.ForwardPayloadLength]
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
