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
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx"
	sphinxcommands "github.com/katzenpost/core/sphinx/commands"
	sphinxconstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
	"github.com/stretchr/testify/require"
)

func newMixDescriptor(isProvider bool, name string, layer int, publicKey *ecdh.PublicKey, ip string, port int) *pki.MixDescriptor {
	id := [sphinxconstants.NodeIDLength]byte{}
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

func newMixPKI(require *require.Assertions) (pki.Client, map[string]*ecdh.PrivateKey, map[[sphinxconstants.NodeIDLength]byte]*ecdh.PrivateKey) {
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

	providerMap := make(map[string]*ecdh.PrivateKey)
	mixMap := make(map[[sphinxconstants.NodeIDLength]byte]*ecdh.PrivateKey)
	staticPKI := mix_pki.NewStaticPKI()
	for _, provider := range test_providers {
		privKey, err := ecdh.NewKeypair(rand.Reader)
		require.NoError(err, "ecdh NewKeypair error")
		descriptor := newMixDescriptor(true, provider.Name, provider.Layer, privKey.PublicKey(), provider.IP, provider.Port)
		providerMap[provider.Name] = privKey
		staticPKI.ProviderMap[descriptor.Name] = descriptor
		staticPKI.MixMap[descriptor.ID] = descriptor
	}
	for _, mix := range test_mixes {
		privKey, err := ecdh.NewKeypair(rand.Reader)
		require.NoError(err, "ecdh NewKeypair error")
		descriptor := newMixDescriptor(true, mix.Name, mix.Layer, privKey.PublicKey(), mix.IP, mix.Port)
		mixMap[descriptor.ID] = privKey
		staticPKI.MixMap[descriptor.ID] = descriptor
	}
	return staticPKI, providerMap, mixMap
}

type MockSession struct {
	sentCommands []commands.Command
}

func (m *MockSession) Initialize(conn net.Conn) error {
	return nil
}

func (m *MockSession) SendCommand(cmd commands.Command) error {
	m.sentCommands = append(m.sentCommands, cmd)
	return nil
}

func (m *MockSession) RecvCommand() (commands.Command, error) {
	return commands.NoOp{}, nil
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
		Sessions: make(map[string]wire.SessionInterface),
		Locks:    make(map[string]*sync.Mutex),
	}
	pool.Add(identity, mockSession)

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

func decryptSphinxLayers(t *testing.T, require *require.Assertions, sphinxPacket []byte, providerKey *ecdh.PrivateKey, mixMap map[[sphinxconstants.NodeIDLength]byte]*ecdh.PrivateKey) []byte {
	var payload []byte
	_, _, routingInfo, err := sphinx.Unwrap(providerKey, sphinxPacket)
	require.NoError(err, "sphinx.Unwrap failure")
	terminalHop := false
	var mixKey *ecdh.PrivateKey
	for !terminalHop {
	L:
		for _, routingCommand := range routingInfo {
			switch cmd := routingCommand.(type) {
			case *sphinxcommands.NextNodeHop:
				mixKey = mixMap[cmd.ID]
				t.Logf("NextNodeHop command: %x", cmd.ID)
				break L
			case *sphinxcommands.Recipient:
				t.Logf("Recipient command: %s", cmd.ID)
				break L
			}
		}
		payload, _, routingInfo, err = sphinx.Unwrap(mixKey, sphinxPacket)
		require.NoError(err, "sphinx.Unwrap failure")
	}
	return payload
}

func TestSender(t *testing.T) {
	require := require.New(t)

	mixPKI, providerMap, mixMap := newMixPKI(require)
	nrHops := 4
	lambda := float64(.123)
	routeFactory := path_selection.New(mixPKI, nrHops, lambda)

	aliceEmail := "alice@acme.com"
	alicePool, aliceStore, alicePrivKey, aliceBlockHandler := makeUser(require, aliceEmail)

	bobEmail := "bob@nsa.gov"
	bobPool, bobStore, bobPrivKey, bobBlockHandler := makeUser(require, bobEmail)

	userPKI := MockUserPKI{
		userMap: map[string]*ecdh.PublicKey{
			aliceEmail: alicePrivKey.PublicKey(),
			bobEmail:   bobPrivKey.PublicKey(),
		},
	}

	aliceSender, err := NewSender("alice@acme.com", alicePool, aliceStore, routeFactory, userPKI, aliceBlockHandler)
	require.NoError(err, "NewSender failure")

	bobSender, err := NewSender("bob@nsa.gov", bobPool, bobStore, routeFactory, userPKI, bobBlockHandler)
	require.NoError(err, "NewSender failure")

	// Alice sends message to Bob
	bobID := [sphinxconstants.RecipientIDLength]byte{}
	copy(bobID[:], "bob")
	toBobBlock := block.Block{
		TotalBlocks: 1,
		Block:       []byte("yo bobby, what up?"),
	}
	aliceStorageBlock := storage.StorageBlock{
		Sender:            "alice@acme.com",
		SenderProvider:    "acme.com",
		Recipient:         "bob@nsa.gov",
		RecipientProvider: "nsa.gov",
		RecipientID:       bobID,
		Block:             toBobBlock,
	}
	blockID, err := aliceStore.PutEgressBlock(&aliceStorageBlock)
	rtt, err := aliceSender.Send(blockID, &aliceStorageBlock)
	require.NoError(err, "Send failure")
	t.Logf("Alice send rtt %d", rtt)

	// decrypt Alice's captured sphinx packet
	session := alicePool.Sessions["alice@acme.com"]
	mockSession, ok := session.(*MockSession)
	require.True(ok, "failed to get MockSession")
	sendPacket, ok := mockSession.sentCommands[0].(*commands.SendPacket)
	require.True(ok, "failed to get SendPacket command")
	aliceProviderKey := providerMap["acme.com"]
	_ = decryptSphinxLayers(t, require, sendPacket.SphinxPacket, aliceProviderKey, mixMap)

	// Bob sends message to Alice
	aliceID := [sphinxconstants.RecipientIDLength]byte{}
	copy(aliceID[:], "alice")
	toAliceBlock := block.Block{
		TotalBlocks: 1,
		Block:       []byte("Alice, I have the documents you requested."),
	}
	bobStorageBlock := storage.StorageBlock{
		Sender:            "bob@nsa.gov",
		SenderProvider:    "nsa.gov",
		Recipient:         "alice@acme.com",
		RecipientProvider: "acme.com",
		RecipientID:       aliceID,
		Block:             toAliceBlock,
	}
	blockID, err = bobStore.PutEgressBlock(&bobStorageBlock)
	rtt, err = bobSender.Send(blockID, &bobStorageBlock)
	require.NoError(err, "Send failure")
	t.Logf("Bob send rtt %d", rtt)
}
