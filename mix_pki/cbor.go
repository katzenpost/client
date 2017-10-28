// json.go - mixnet PKI client which uses json files
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

// Package provides mix PKI client implementations
package mix_pki

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"

	"github.com/2tvenom/cbor"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/pki"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("mixclient")

type StaticPKI struct {
	epochMap map[uint64]*pki.Document
}

func (t *StaticPKI) Set(epoch uint64, doc *pki.Document) error {
	_, ok := t.epochMap[epoch]
	if ok {
		return errors.New("wtf")
	}
	t.epochMap[epoch] = doc
	return nil
}

func (t *StaticPKI) Get(ctx context.Context, epoch uint64) (*pki.Document, error) {
	val, ok := t.epochMap[epoch]
	if !ok {
		return nil, errors.New("static pki key lookup failure")
	}
	return val, nil
}

func NewStaticPKI() *StaticPKI {
	staticPKI := StaticPKI{
		epochMap: make(map[uint64]*pki.Document),
	}
	return &staticPKI
}

type CBORStaticPKI struct {
	EpochMap map[uint64]*pki.CBORDocument
}

func StaticPKIFromFile(pkiFile string) (*StaticPKI, error) {
	epochMap := make(map[uint64]*pki.Document)
	cborEpochMap := make(map[uint64]*pki.CBORDocument)
	var buffTest bytes.Buffer
	encoder := cbor.NewEncoder(&buffTest)
	b, err := ioutil.ReadFile(pkiFile)
	if err != nil {
		return nil, err
	}
	_, err = encoder.Unmarshal(b, &cborEpochMap)
	if err != nil {
		return nil, err
	}
	for k, v := range cborEpochMap {
		epochMap[k] = v.ToDocument()
	}
	p := StaticPKI{
		epochMap: epochMap,
	}
	return &p, nil
}

// DocsToCBOR takes a slice of Document structs and
// returns the CBOR serialized output bytes
func DocsToCBOR(documents []pki.Document) ([]byte, error) {
	newDocs := []pki.CBORDocument{}
	for _, doc := range documents {
		cborDoc := doc.ToCBORDocument()
		newDocs = append(newDocs, *cborDoc)
	}
	var buffTest bytes.Buffer
	encoder := cbor.NewEncoder(&buffTest)
	ok, err := encoder.Marshal(newDocs)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("wtf")
	}
	return buffTest.Bytes(), nil
}

func CBORKeysFromMap(keysMap map[ecdh.PublicKey]*ecdh.PrivateKey) ([]byte, error) {
	newMap := make(map[[32]byte][32]byte)
	for k, v := range keysMap {
		key := [32]byte{}
		copy(key[:], k.Bytes())
		val := [32]byte{}
		copy(val[:], v.Bytes())
		newMap[key] = val
	}
	var buffTest bytes.Buffer
	encoder := cbor.NewEncoder(&buffTest)
	ok, err := encoder.Marshal(newMap)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("wtf")
	}
	return buffTest.Bytes(), nil
}
