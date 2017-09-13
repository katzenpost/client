// block.go - End to end encrypted/authenticated block routines.
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

// Package block provides end to end encrypted/authenticated blocks.
package block

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/katzenpost/client/constants"
	coreConstants "github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/noise"
)

const (
	// BlockLength is the maximum payload size of a Block in bytes.
	BlockLength         = coreConstants.ForwardPayloadLength + (blockCipherOverhead + blockOverhead)
	blockCipherOverhead = keyLen + macLen + keyLen + macLen // -> e, es, s, ss
	blockOverhead       = 24

	totalOff = constants.MessageIDLength
	idOff    = totalOff + 2
	lenOff   = idOff + 2
	blockOff = lenOff + 4

	// It's dumb that the noise library doesn't have these.
	macLen = 16
	keyLen = 32
)

// Block is a de-serialized block.
type Block struct {
	MessageID   [constants.MessageIDLength]byte
	TotalBlocks uint16
	BlockID     uint16
	// BlockLength uint32
	Block []byte
	// Padding     []byte
}

// JsonBlock is used to serialize a Block to JSON format
type JsonBlock struct {
	MessageID   string
	TotalBlocks int
	BlockID     int
	Block       string
}

// ToBlock deserializes a JsonBlock into a Block
func (j *JsonBlock) ToBlock() (*Block, error) {
	b := Block{
		TotalBlocks: uint16(j.TotalBlocks),
		BlockID:     uint16(j.BlockID),
	}
	messageID, err := base64.StdEncoding.DecodeString(j.MessageID)
	if err != nil {
		return nil, err
	}
	copy(b.MessageID[:], messageID)
	b.Block, err = base64.StdEncoding.DecodeString(j.Block)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ToJsonBlock is used to serialize a Block into a JsonBlock
func (b *Block) ToJsonBlock() *JsonBlock {
	j := JsonBlock{
		MessageID:   base64.StdEncoding.EncodeToString(b.MessageID[:]),
		TotalBlocks: int(b.TotalBlocks),
		BlockID:     int(b.BlockID),
		Block:       base64.StdEncoding.EncodeToString(b.Block),
	}
	return &j
}

// ToBytes serializes a Block into bytes
func (b *Block) ToBytes() []byte {
	fmt.Printf("b.Block len is %d and max block len is %d\n", len(b.Block), BlockLength)
	if len(b.Block) > BlockLength {
		panic(fmt.Sprintf("client/block: oversized Block payload; %d > %d BlockLength", len(b.Block), BlockLength))
	}

	var zeroBytes [BlockLength]byte

	out := make([]byte, blockOverhead, blockOverhead+BlockLength)
	copy(out, b.MessageID[:])
	binary.BigEndian.PutUint16(out[totalOff:], b.TotalBlocks)
	binary.BigEndian.PutUint16(out[idOff:], b.BlockID)
	binary.BigEndian.PutUint32(out[lenOff:], uint32(len(b.Block)))
	out = append(out, b.Block...)
	out = append(out, zeroBytes[:BlockLength-len(b.Block)]...)

	return out
}

// FromBytes deserializes bytes in JSON format to a Block
// or it returns an error if any
func FromBytes(raw []byte) (*Block, error) {
	if len(raw) != blockOverhead+BlockLength {
		return nil, errors.New("client/block: invalid block size")
	}

	b := new(Block)
	copy(b.MessageID[:], raw[:totalOff])
	b.TotalBlocks = binary.BigEndian.Uint16(raw[totalOff:idOff])
	b.BlockID = binary.BigEndian.Uint16(raw[idOff:lenOff])
	blockLen := binary.BigEndian.Uint32(raw[lenOff:blockOff])
	b.Block = make([]byte, blockLen)
	copy(b.Block, raw[blockOff:blockOff+blockLen])
	if !utils.CtIsZero(raw[blockOff+blockLen:]) {
		return nil, errors.New("client/block: invalid padding")
	}
	return b, nil
}

// Handler is a block plaintext/ciphertext handler.
type Handler struct {
	identityKey *ecdh.PrivateKey
	cipherSuite noise.CipherSuite
	randReader  io.Reader
}

// NewHandler creates a new Handler instance capable of encrypting/decrypting
// Block(s) with the supplied private key.
func NewHandler(identityKey *ecdh.PrivateKey, rand io.Reader) *Handler {
	h := &Handler{
		identityKey: identityKey,
		cipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
		randReader:  rand,
	}
	return h
}

// Encrypt encrypts the Block for the public key.
func (h *Handler) Encrypt(publicKey *ecdh.PublicKey, b *Block) []byte {
	hs := noise.NewHandshakeState(noise.Config{
		CipherSuite: h.cipherSuite,
		Random:      h.randReader,
		Pattern:     noise.HandshakeX,
		Initiator:   true,
		StaticKeypair: noise.DHKey{
			Private: h.identityKey.Bytes(),
			Public:  h.identityKey.PublicKey().Bytes(),
		},
		PeerStatic: publicKey.Bytes(),
	})
	plaintext := b.ToBytes()
	ciphertext := make([]byte, 0, blockCipherOverhead+blockOverhead+len(plaintext))
	ciphertext, _, _ = hs.WriteMessage(ciphertext, plaintext)
	return ciphertext
}

// Decrypt decrypts and authenticates the Block, and returns the de-serialized
// Block, and the identity key of the originator.
func (h *Handler) Decrypt(ciphertext []byte) (*Block, *ecdh.PublicKey, error) {
	hs := noise.NewHandshakeState(noise.Config{
		CipherSuite: h.cipherSuite,
		Random:      h.randReader,
		Pattern:     noise.HandshakeX,
		Initiator:   false,
		StaticKeypair: noise.DHKey{
			Private: h.identityKey.Bytes(),
			Public:  h.identityKey.PublicKey().Bytes(),
		},
	})
	plaintext, _, _, err := hs.ReadMessage(nil, ciphertext)
	if err != nil {
		return nil, nil, err
	}

	// Parse the block, serialize the peer public key.
	b, err := FromBytes(plaintext)
	if err != nil {
		return nil, nil, err
	}
	peerIdentityKey := new(ecdh.PublicKey)
	if err = peerIdentityKey.FromBytes(hs.PeerStatic()); err != nil {
		return nil, nil, err
	}

	return b, peerIdentityKey, nil
}
