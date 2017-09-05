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
	"io"
	"math"

	clientconstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/crypto/block"
	"github.com/katzenpost/core/constants"
)

//func reassembleMessage([]*block.Block) ([]byte, error) {
//}

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
