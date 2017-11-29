// send_test.go - mix network client send tests
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

package proxy

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/client/crypto/block"
	"github.com/katzenpost/client/mix_pki"
	"github.com/katzenpost/client/path_selection"
	"github.com/katzenpost/client/session_pool"
	"github.com/katzenpost/client/storage"
	coreconstants "github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx"
	sphinxconstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
	"github.com/stretchr/testify/require"
)

type MixDescriptorSecrets struct {
	epochSecrets map[ecdh.PublicKey]*ecdh.PrivateKey
}

func createMixDescriptor(name string, layer uint8, addresses []string, startEpoch, endEpoch uint64) (*pki.MixDescriptor, *MixDescriptorSecrets, error) {
	mixKeys := make(map[uint64]*ecdh.PublicKey)
	epochSecrets := make(map[ecdh.PublicKey]*ecdh.PrivateKey)
	identityPrivKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	for i := startEpoch; i < endEpoch+1; i++ {
		mixPrivKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		mixKeys[i] = mixPrivKey.PublicKey()
		pubKey := mixPrivKey.PublicKey()
		epochSecrets[*pubKey] = mixPrivKey
	}
	secrets := MixDescriptorSecrets{
		epochSecrets: epochSecrets,
	}
	descriptor := pki.MixDescriptor{
		Name:        name,
		IdentityKey: identityPrivKey.PublicKey(),
		MixKeys:     mixKeys,
		Addresses:   addresses,
		Layer:       layer,
		LoadWeight:  0,
	}
	return &descriptor, &secrets, nil
}

func newMixPKI(require *require.Assertions) (pki.Client, map[ecdh.PublicKey]*ecdh.PrivateKey) {
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

	layerMax := uint8(3)
	keysMap := make(map[ecdh.PublicKey]*ecdh.PrivateKey)
	staticPKI := mix_pki.NewStaticPKI()
	startEpoch, _, _ := epochtime.Now()
	providers := []*pki.MixDescriptor{}
	mixes := []*pki.MixDescriptor{}
	for _, provider := range test_providers {
		mockAddr := []string{} // XXX fix me?
		descriptor, descriptorSecrets, err := createMixDescriptor(provider.Name, uint8(provider.Layer), mockAddr, startEpoch, startEpoch+3)
		require.NoError(err, "createMixDescriptor errored")
		providers = append(providers, descriptor)
		for pubKey, privKey := range descriptorSecrets.epochSecrets {
			keysMap[pubKey] = privKey
		}
	}
	for _, mix := range test_mixes {
		mockAddr := []string{} // XXX fix me?
		descriptor, descriptorSecrets, err := createMixDescriptor(mix.Name, uint8(mix.Layer), mockAddr, startEpoch, startEpoch+3)
		require.NoError(err, "createMixDescriptor errored")
		mixes = append(mixes, descriptor)
		for pubKey, privKey := range descriptorSecrets.epochSecrets {
			keysMap[pubKey] = privKey
		}
	}

	// for each epoch create a PKI Document and index it by epoch
	for current := startEpoch; current < startEpoch+3+1; current++ {
		pkiDocument := pki.Document{
			Epoch:    current,
			Lambda:   float64(.00123),
			MaxDelay: uint64(666),
		}
		// topology
		pkiDocument.Topology = make([][]*pki.MixDescriptor, layerMax+1)
		for i := uint8(0); i < layerMax; i++ {
			pkiDocument.Topology[i] = make([]*pki.MixDescriptor, 0)
		}
		for i := uint8(0); i < layerMax+1; i++ {
			for _, mix := range mixes {
				if mix.Layer == i {
					pkiDocument.Topology[i] = append(pkiDocument.Topology[i], mix)
				}
			}
		}
		// providers
		for _, provider := range providers {
			pkiDocument.Providers = append(pkiDocument.Providers, provider)
		}
		// setup our epoch -> document map
		staticPKI.Set(current, &pkiDocument)
	}
	return staticPKI, keysMap
}

type MockSession struct {
	sentCommands []commands.Command
	recvCommands []commands.Command
}

func (m *MockSession) Initialize(conn net.Conn) error {
	return nil
}

func (m *MockSession) SendCommand(cmd commands.Command) error {
	m.sentCommands = append(m.sentCommands, cmd)
	return nil
}

func (m *MockSession) RecvCommand() (commands.Command, error) {
	if len(m.recvCommands) == 0 {
		return commands.MessageEmpty{}, nil
	}
	retCmd := m.recvCommands[len(m.recvCommands)-1]
	if len(m.recvCommands)-1 == 0 {
		m.recvCommands = []commands.Command{}
	} else {
		m.recvCommands = m.recvCommands[:len(m.recvCommands)-2]
	}
	return retCmd, nil
}

func (m *MockSession) Close() {}

func (m *MockSession) PeerCredentials() *wire.PeerCredentials {
	return nil
}

func (m *MockSession) ClockSkew() time.Duration {
	return 0
}

type MockUserPKI struct {
	userMap map[string]*ecdh.PublicKey
}

func (m MockUserPKI) GetKey(email string) (*ecdh.PublicKey, error) {
	value, ok := m.userMap[strings.ToLower(email)]
	if !ok {
		return nil, errors.New("json user pki email lookup failed")
	}
	return value, nil
}

func makeUser(require *require.Assertions, identity string) (*session_pool.SessionPool, *storage.Store, *ecdh.PrivateKey, *block.Handler) {
	mockSession := &MockSession{}
	pool := &session_pool.SessionPool{
		Sessions:     make(map[string]wire.SessionInterface),
		SessionLocks: make(map[string]*sync.Mutex),
	}
	pool.Sessions[identity] = mockSession
	pool.SessionLocks[identity] = new(sync.Mutex)

	dbFile, err := ioutil.TempFile("", "db_test_sender")
	require.NoError(err, "unexpected TempFile error")
	defer func() {
		err := os.Remove(dbFile.Name())
		require.NoError(err, "unexpected os.Remove error")
	}()
	store, err := storage.New(dbFile.Name())
	require.NoError(err, "unexpected New() error")

	idKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "Block: Alice NewKeypair()")
	blockHandler := block.NewHandler(idKey, rand.Reader)

	return pool, store, idKey, blockHandler
}

func TestForwardSphinxSize(t *testing.T) {
	require := require.New(t)

	mixPKI, _ := newMixPKI(require)
	routeFactory := path_selection.New(mixPKI, sphinxconstants.NrHops-2)

	senderProvider := "acme.com"
	recipientProvider := "nsa.gov"
	recipientName := "alice"
	recipientID := [sphinxconstants.RecipientIDLength]byte{}
	copy(recipientID[:], []byte(recipientName))
	path, _, _, _, err := routeFactory.Build(senderProvider, recipientProvider, recipientID)
	require.NoError(err, "path selection error")

	payload := [coreconstants.ForwardPayloadLength]byte{}
	pkt, err := sphinx.NewPacket(rand.Reader, path, payload[:])
	require.NoError(err, "NewPacket failed")

	require.Equal(len(pkt), coreconstants.PacketLength, "invalid packet size")
}
