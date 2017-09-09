// path_selection_test.go - path selection tests
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

package path_selection

import (
	"errors"
	"testing"

	"github.com/katzenpost/client/mix_pki"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/require"
)

func newMixDescriptor(isProvider bool, name string, layer int, publicKey *ecdh.PublicKey, ip string, port int) *pki.MixDescriptor {
	id := [constants.NodeIDLength]byte{}
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	d := pki.MixDescriptor{
		Name:            name,
		ID:              id,
		IsProvider:      isProvider,
		LoadWeight:      3,
		TopologyLayer:   uint8(layer),
		EpochAPublicKey: publicKey,
		Ipv4Address:     ip,
		TcpPort:         port,
	}
	return &d
}

func newMixPKI(require *require.Assertions) (pki.Client, map[[constants.NodeIDLength]byte]*ecdh.PrivateKey) {
	type testDesc struct {
		Name  string
		Layer int
		IP    string
		Port  int
	}

	test_providers := []testDesc{
		{
			Name:  "acme.com",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11240,
		},
		{
			Name:  "nsa.gov",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11241,
		},
		{
			Name:  "gchq.uk",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11242,
		},
		{
			Name:  "fsb.ru",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11243,
		},
	}

	test_mixes := []testDesc{
		{
			Name:  "nsamix101",
			Layer: 1,
			IP:    "127.0.0.1",
			Port:  11234,
		},
		{
			Name:  "nsamix102",
			Layer: 2,
			IP:    "127.0.0.1",
			Port:  112345,
		},
		{
			Name:  "five_eyes",
			Layer: 3,
			IP:    "127.0.0.1",
			Port:  11236,
		},
		{
			Name:  "gchq123",
			Layer: 1,
			IP:    "127.0.0.1",
			Port:  11237,
		},
		{
			Name:  "fsbspy1",
			Layer: 2,
			IP:    "127.0.0.1",
			Port:  11238,
		},
		{
			Name:  "foxtrot2",
			Layer: 3,
			IP:    "127.0.0.1",
			Port:  11239,
		},
	}

	keysMap := make(map[[constants.NodeIDLength]byte]*ecdh.PrivateKey)
	staticPKI := mix_pki.NewStaticPKI()
	for _, provider := range test_providers {
		privKey, err := ecdh.NewKeypair(rand.Reader)
		require.NoError(err, "ecdh NewKeypair error")
		descriptor := newMixDescriptor(true, provider.Name, provider.Layer, privKey.PublicKey(), provider.IP, provider.Port)
		keysMap[descriptor.ID] = privKey
		staticPKI.ProviderMap[descriptor.Name] = descriptor
		staticPKI.MixMap[descriptor.ID] = descriptor
	}
	for _, mix := range test_mixes {
		privKey, err := ecdh.NewKeypair(rand.Reader)
		require.NoError(err, "ecdh NewKeypair error")
		descriptor := newMixDescriptor(true, mix.Name, mix.Layer, privKey.PublicKey(), mix.IP, mix.Port)
		keysMap[descriptor.ID] = privKey
		staticPKI.MixMap[descriptor.ID] = descriptor
	}
	return staticPKI, keysMap
}

func TestPathSelection(t *testing.T) {
	require := require.New(t)
	mixPKI, _ := newMixPKI(require)
	nrHops := 4
	lambda := float64(.123)
	factory := New(mixPKI, nrHops, lambda)

	senderProvider := "acme.com"
	recipientProvider := "nsa.gov"
	recipientName := "alice"
	recipientID := [constants.RecipientIDLength]byte{}
	copy(recipientID[:], []byte(recipientName))
	forwardRoute, replyRoute, surbID, rtt, err := factory.Build(senderProvider, recipientProvider, recipientID)
	require.NoError(err, "build route error")
	require.NotNil(surbID, "surbID should NOT be nil")
	t.Logf("built a forward path %s", forwardRoute)
	t.Logf("built a reply path %s", replyRoute)
	t.Logf("rtt is %s", rtt)
	t.Logf("surb ID %v", *surbID)
}

type MockErrorPKI struct {
	errProvider    bool
	errGetMixes    bool
	providerErrNum int
}

func (m *MockErrorPKI) GetLatestConsensusMap() *map[[constants.NodeIDLength]byte]*pki.MixDescriptor {
	return nil
}

func (m *MockErrorPKI) GetProviderDescriptor(name string) (*pki.MixDescriptor, error) {
	if m.errProvider {
		m.providerErrNum = m.providerErrNum - 1
		if m.providerErrNum > 0 {
			return nil, errors.New("GetProviderDescriptor failure")
		} else {
			privKey, _ := ecdh.NewKeypair(rand.Reader)
			descriptor := newMixDescriptor(true, "acme.com", 0, privKey.PublicKey(), "127.0.0.1", 666)
			return descriptor, nil
		}
	}
	return nil, nil
}

func (m *MockErrorPKI) GetMixesInLayer(layer uint8) []*pki.MixDescriptor {
	if m.errGetMixes {
		return []*pki.MixDescriptor{}
	}
	return []*pki.MixDescriptor{&pki.MixDescriptor{}}
}

func (m *MockErrorPKI) GetDescriptor(id [constants.NodeIDLength]byte) (*pki.MixDescriptor, error) {
	return nil, nil
}

func TestGetRouteDescriptorsErrors(t *testing.T) {
	require := require.New(t)

	pki := MockErrorPKI{
		errProvider:    true,
		providerErrNum: 5,
	}
	nrHops := 4
	lambda := float64(.123)
	factory := New(&pki, nrHops, lambda)

	senderProvider := "acme.com"
	recipientProvider := "nsa.gov"
	recipientID := [constants.RecipientIDLength]byte{}
	_, _, _, _, err := factory.Build(senderProvider, recipientProvider, recipientID)
	require.Error(err, "Build should have errored")
}
