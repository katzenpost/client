// remote_spool.go - client session remote spool operations
// Copyright (C) 2019  David Stainton.
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

package session

import (
	"errors"
	"fmt"
	"strings"

	"github.com/katzenpost/client/multispool"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/minclient/block"
)

const (
	OKStatus     = "OK"
	SpoolService = "spool"
)

func (s *Session) submitCommand(cmd []byte, recipient, provider string) (*multispool.SpoolResponse, error) {
	reply, err := s.SendUnreliableMessage(recipient, provider, cmd)
	if err != nil {
		return nil, err
	}
	spoolResponse, err := multispool.SpoolResponseFromBytes(reply)
	if err != nil {
		return nil, err
	}
	if strings.Compare(spoolResponse.Status, OKStatus) == 0 {
		return &spoolResponse, nil
	}

	return nil, fmt.Errorf("spool command failure: %s", spoolResponse.Status)
}

func (s *Session) CreateSpool(privKey *eddsa.PrivateKey, recipient, provider string) ([]byte, error) {
	cmd, err := multispool.CreateSpool(privKey)
	if err != nil {
		return nil, err
	}
	spoolResponse, err := s.submitCommand(cmd, recipient, provider)
	if err != nil {
		return nil, err
	}
	return spoolResponse.SpoolID, nil
}

func (s *Session) PurgeSpool(spoolID []byte, privKey *eddsa.PrivateKey, recipient, provider string) error {
	if len(spoolID) != multispool.SpoolIDSize {
		return errors.New("spoolID wrong size")
	}
	_spoolID := [multispool.SpoolIDSize]byte{}
	copy(_spoolID[:], spoolID)
	cmd, err := multispool.PurgeSpool(_spoolID, privKey)
	if err != nil {
		return err
	}
	_, err = s.submitCommand(cmd, recipient, provider)
	return err
}

func (s *Session) AppendToSpool(spoolID []byte, message []byte, recipient, provider string) error {
	if len(spoolID) != multispool.SpoolIDSize {
		return errors.New("spoolID wrong size")
	}
	_spoolID := [multispool.SpoolIDSize]byte{}
	copy(_spoolID[:], spoolID)
	cmd, err := multispool.AppendToSpool(_spoolID, message)
	if err != nil {
		return err
	}
	_, err = s.submitCommand(cmd, recipient, provider)
	return err
}

func (s *Session) ReadFromSpool(spoolID []byte, messageID uint32,
	privKey *eddsa.PrivateKey,
	recipient,
	provider string) (*multispool.SpoolResponse, error) {
	s.log.Debugf("ReadFromSpool MESSAGE ID %d", messageID)
	if len(spoolID) != multispool.SpoolIDSize {
		return nil, errors.New("spoolID wrong size")
	}
	_spoolID := [multispool.SpoolIDSize]byte{}
	copy(_spoolID[:], spoolID)
	cmd, err := multispool.ReadFromSpool(_spoolID, messageID, privKey)
	if err != nil {
		return nil, err
	}
	return s.submitCommand(cmd, recipient, provider)
}

type UnreliableSpoolReader struct {
	session               *Session
	spoolProvider         string
	spoolReceiver         string
	spoolID               []byte
	spoolPrivateKey       *eddsa.PrivateKey
	noisePrivateKey       *ecdh.PrivateKey
	partnerNoisePublicKey *ecdh.PublicKey
	spoolIndex            uint32
}

func CreateUnreliableSpoolReader(session *Session, partnerNoisePublicKey *ecdh.PublicKey) (*UnreliableSpoolReader, error) {
	descriptor, err := session.GetService(SpoolService)
	if err != nil {
		return nil, err
	}
	spoolPrivateKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	noisePrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	spoolID, err := session.CreateSpool(spoolPrivateKey, descriptor.Name, descriptor.Provider)
	if err != nil {
		return nil, err
	}
	return &UnreliableSpoolReader{
		session:               session,
		spoolProvider:         descriptor.Provider,
		spoolReceiver:         descriptor.Name,
		spoolID:               spoolID,
		spoolPrivateKey:       spoolPrivateKey,
		noisePrivateKey:       noisePrivateKey,
		partnerNoisePublicKey: partnerNoisePublicKey,
		spoolIndex:            1,
	}, nil
}

func (r *UnreliableSpoolReader) Read() ([]byte, error) {
	spoolResponse, err := r.session.ReadFromSpool(r.spoolID[:], r.spoolIndex, r.spoolPrivateKey, r.spoolReceiver, r.spoolProvider)
	if err != nil {
		return nil, err
	}
	if spoolResponse.Status != "OK" {
		return nil, errors.New(spoolResponse.Status)
	}
	r.spoolIndex++
	block, pubKey, err := block.DecryptBlock(spoolResponse.Message, r.noisePrivateKey)
	if err != nil {
		return nil, err
	}
	if !r.partnerNoisePublicKey.Equal(pubKey) {
		return nil, errors.New("wtf, wrong partner Noise X key")
	}
	if block.TotalBlocks != 1 {
		return nil, errors.New("block error, one block per message required")
	}
	return block.Payload, nil
}

type UnreliableSpoolWriter struct {
	session               *Session
	spoolProvider         string
	spoolReceiver         string
	spoolID               []byte
	noisePrivateKey       *ecdh.PrivateKey
	partnerNoisePublicKey *ecdh.PublicKey
}

func CreateUnreliableSpoolWriter(session *Session, spoolID []byte, spoolReceiver string, spoolProvider string, partnerNoisePublicKey *ecdh.PublicKey) (*UnreliableSpoolWriter, error) {
	noisePrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &UnreliableSpoolWriter{
		session:               session,
		spoolProvider:         spoolProvider,
		spoolReceiver:         spoolReceiver,
		spoolID:               spoolID,
		noisePrivateKey:       noisePrivateKey,
		partnerNoisePublicKey: partnerNoisePublicKey,
	}, nil
}

func (r *UnreliableSpoolWriter) Write(message []byte) error {
	mesgID := [block.MessageIDLength]byte{}
	_, err := rand.NewMath().Read(mesgID[:])
	if err != nil {
		return nil
	}
	blocks, err := block.EncryptMessage(&mesgID, message, r.noisePrivateKey, r.partnerNoisePublicKey)
	if err != nil {
		return nil
	}
	if len(blocks) != 1 {
		return errors.New("message fragmentation not yet supported")
	}
	err = r.session.AppendToSpool(r.spoolID[:], message, r.spoolReceiver, r.spoolProvider)
	return err
}

type UnreliableSpoolReaderWriter struct {
	reader *UnreliableSpoolReader
	writer *UnreliableSpoolWriter
}

func (s *UnreliableSpoolReaderWriter) Read() ([]byte, error) {
	return s.reader.Read()
}

func (s *UnreliableSpoolReaderWriter) Write(message []byte) error {
	return s.writer.Write(message)
}
