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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("mixclient")

type JsonMixDescriptor struct {
	Name            string
	ID              string
	IsProvider      bool
	LoadWeight      int
	TopologyLayer   int
	EpochAPublicKey string
	EpochBPublicKey string
	EpochCPublicKey string
	Ipv4Address     string
	TcpPort         int
}

type JsonStaticPKI struct {
	MixDescriptors []JsonMixDescriptor
}

func JsonFromDescriptor(m *pki.MixDescriptor) *JsonMixDescriptor {
	desc := JsonMixDescriptor{
		Name:            m.Name,
		ID:              base64.StdEncoding.EncodeToString(m.ID[:]),
		IsProvider:      m.IsProvider,
		LoadWeight:      int(m.LoadWeight),
		TopologyLayer:   int(m.TopologyLayer),
		EpochAPublicKey: base64.StdEncoding.EncodeToString(m.EpochAPublicKey.Bytes()),
		EpochBPublicKey: base64.StdEncoding.EncodeToString(m.EpochBPublicKey.Bytes()),
		EpochCPublicKey: base64.StdEncoding.EncodeToString(m.EpochCPublicKey.Bytes()),
		Ipv4Address:     m.Ipv4Address,
		TcpPort:         m.TcpPort,
	}
	return &desc
}

func (j *JsonMixDescriptor) MixDescriptor() (*pki.MixDescriptor, error) {
	idBytes, err := base64.StdEncoding.DecodeString(j.ID)
	if err != nil {
		return nil, err
	}
	var id [constants.NodeIDLength]byte
	copy(id[:], idBytes)
	aBytes, err := base64.StdEncoding.DecodeString(j.EpochAPublicKey)
	if err != nil {
		return nil, err
	}
	keyA := ecdh.PublicKey{}
	keyA.FromBytes(aBytes)
	d := pki.MixDescriptor{
		Name:            strings.ToLower(j.Name),
		ID:              id,
		IsProvider:      j.IsProvider,
		LoadWeight:      uint8(j.LoadWeight),
		TopologyLayer:   uint8(j.TopologyLayer),
		EpochAPublicKey: &keyA,
		Ipv4Address:     j.Ipv4Address,
		TcpPort:         j.TcpPort,
	}
	return &d, nil
}

type StaticPKI struct {
	MixMap      map[[constants.NodeIDLength]byte]*pki.MixDescriptor
	ProviderMap map[string]*pki.MixDescriptor
}

func NewStaticPKI() *StaticPKI {
	staticPKI := StaticPKI{
		MixMap:      make(map[[constants.NodeIDLength]byte]*pki.MixDescriptor),
		ProviderMap: make(map[string]*pki.MixDescriptor),
	}
	return &staticPKI
}

func (t *StaticPKI) GetDescriptor(id [constants.NodeIDLength]byte) (*pki.MixDescriptor, error) {
	mix, ok := t.MixMap[id]
	if ok {
		return mix, nil
	}
	return nil, errors.New("mix id not found in static consensus")
}

func (t *StaticPKI) GetMixesInLayer(layer uint8) []*pki.MixDescriptor {
	l := []*pki.MixDescriptor{}
	for _, v := range t.MixMap {
		if v.TopologyLayer == layer {
			l = append(l, v)
		}
	}
	return l
}

func (t *StaticPKI) GetLatestConsensusMap() *map[[constants.NodeIDLength]byte]*pki.MixDescriptor {
	return &t.MixMap
}

func (t *StaticPKI) GetProviderDescriptor(name string) (*pki.MixDescriptor, error) {
	log.Debugf("GET PROVIDER DESCRIPTOR: %s", name)
	v, ok := t.ProviderMap[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("provider descriptor name not found: %s", name)
	}
	return v, nil
}

func StaticPKIFromFile(filePath string) (*StaticPKI, error) {
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	jsonPKI := JsonStaticPKI{}
	err = json.Unmarshal(fileData, &jsonPKI)
	if err != nil {
		return nil, err
	}
	ProviderMap := make(map[string]*pki.MixDescriptor)
	MixMap := make(map[[constants.NodeIDLength]byte]*pki.MixDescriptor)

	for _, mixDesc := range jsonPKI.MixDescriptors {
		idBytes, err := base64.StdEncoding.DecodeString(mixDesc.ID)
		if err != nil {
			return nil, err
		}
		var id [constants.NodeIDLength]byte
		copy(id[:], idBytes)
		if mixDesc.IsProvider {
			ProviderMap[mixDesc.Name], err = mixDesc.MixDescriptor()
		} else {
			MixMap[id], err = mixDesc.MixDescriptor()
		}
		if err != nil {
			return nil, err
		}
	}
	staticPKI := StaticPKI{
		MixMap:      MixMap,
		ProviderMap: ProviderMap,
	}
	return &staticPKI, nil
}
