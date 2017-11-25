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
	"context"
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
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx"
	sphinxcommands "github.com/katzenpost/core/sphinx/commands"
	sphinxconstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
	"github.com/stretchr/testify/require"
)

type MixDescriptorSecrets struct {
	linkPrivKey  *ecdh.PrivateKey
	epochSecrets map[ecdh.PublicKey]*ecdh.PrivateKey
}

func createMixDescriptor(name string, layer uint8, addresses []string, startEpoch, endEpoch uint64) (*pki.MixDescriptor, *MixDescriptorSecrets, error) {
	linkPrivKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	mixKeys := make(map[uint64]*ecdh.PublicKey)
	epochSecrets := make(map[ecdh.PublicKey]*ecdh.PrivateKey)
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
		linkPrivKey:  linkPrivKey,
		epochSecrets: epochSecrets,
	}
	descriptor := pki.MixDescriptor{
		Name:       name,
		LinkKey:    linkPrivKey.PublicKey(),
		MixKeys:    mixKeys,
		Addresses:  addresses,
		Layer:      layer,
		LoadWeight: 0,
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
			Epoch: current,
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
		return commands.NoOp{}, nil
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

func decryptSphinxLayers(t *testing.T, require *require.Assertions, sphinxPacket []byte, senderProviderKey *ecdh.PrivateKey, recieverProviderKey *ecdh.PrivateKey, keysMap map[ecdh.PublicKey]*ecdh.PrivateKey, numHops int) ([]byte, error) {
	var err error
	payload := []byte{}
	var routingInfo []sphinxcommands.RoutingCommand
	var hopKey *ecdh.PrivateKey = senderProviderKey
	for i := 0; i < numHops-1; i++ {
		t.Log("Sphinx Unwrap")
		payload, _, routingInfo, err = sphinx.Unwrap(hopKey, sphinxPacket)
		require.NoError(err, "sphinx.Unwrap failure")
		t.Logf("routingInfo len: %d", len(routingInfo))
		for _, routingCommand := range routingInfo {
			require.NotNil(routingCommand, "routing command is nil")
			t.Logf("routing command: %v", routingCommand)
			switch cmd := routingCommand.(type) {
			case *sphinxcommands.NextNodeHop:
				t.Log("NextNodeHop command")
				pubKey := ecdh.PublicKey{}
				err := pubKey.FromBytes(cmd.ID[:])
				if err != nil {
					return nil, err
				}
				hopKey = keysMap[pubKey]
			case *sphinxcommands.NodeDelay:
				t.Log("NodeDelay command")
			case *sphinxcommands.SURBReply:
				t.Log("SURB Reply command")
			case *sphinxcommands.Recipient:
				t.Log("Recipient command")
			}
		}
	}
	t.Log("final Sphinx Unwrap")
	payload, _, _, err = sphinx.Unwrap(recieverProviderKey, sphinxPacket)
	require.NoError(err, "sphinx.Unwrap failure")
	return payload, nil
}

func TestSender(t *testing.T) {
	require := require.New(t)

	const (
		hdrLength    = coreconstants.SphinxPlaintextHeaderLength + sphinx.SURBLength
		flagsPadding = 0
		flagsSURB    = 1
		reserved     = 0
	)

	mixPKI, keysMap := newMixPKI(require)
	nrHops := 5
	lambda := float64(.123)
	maxDelay := uint64(666)
	routeFactory := path_selection.New(mixPKI, nrHops, lambda, maxDelay)

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

	logBackend, err := log.New("send_test", "DEBUG", false)
	require.NoError(err, "failed creating log backend")

	aliceSender, err := NewSender(logBackend, "alice@acme.com", alicePool, aliceStore, routeFactory, userPKI, aliceBlockHandler)
	require.NoError(err, "NewSender failure")

	bobSender, err := NewSender(logBackend, "bob@nsa.gov", bobPool, bobStore, routeFactory, userPKI, bobBlockHandler)
	require.NoError(err, "NewSender failure")

	// Alice sends message to Bob
	bobID := [sphinxconstants.RecipientIDLength]byte{}
	copy(bobID[:], "bob")
	toBobBlock := block.Block{
		TotalBlocks: 1,
		Block:       []byte("yo bobby, what up?"),
	}
	aliceEgressBlock := storage.EgressBlock{
		Sender:            "alice@acme.com",
		SenderProvider:    "acme.com",
		Recipient:         "bob@nsa.gov",
		RecipientProvider: "nsa.gov",
		RecipientID:       bobID,
		Block:             toBobBlock,
	}
	blockID, err := aliceStore.PutEgressBlock(&aliceEgressBlock)
	rtt, err := aliceSender.Send(blockID, &aliceEgressBlock)
	require.NoError(err, "Send failure")
	t.Logf("Alice send rtt %d", rtt)

	// decrypt Alice's captured sphinx packet
	session := alicePool.Sessions["alice@acme.com"]
	mockSession, ok := session.(*MockSession)
	require.True(ok, "failed to get MockSession")
	sendPacket, ok := mockSession.sentCommands[0].(*commands.SendPacket)
	require.True(ok, "failed to get SendPacket command")

	//aliceProviderKey := providerMap["acme.com"]
	epoch, _, _ := epochtime.Now()
	ctx := context.TODO() // XXX
	doc, err := mixPKI.Get(ctx, epoch)
	require.NoError(err, "pki Get failure")
	descriptor, err := doc.GetProvider("acme.com")
	require.NoError(err, "pki GetProvider error")
	aliceProviderKey := keysMap[*descriptor.MixKeys[epoch]]

	//bobProviderKey := providerMap["nsa.gov"]
	descriptor, err = doc.GetProvider("nsa.gov")
	require.NoError(err, "pki GetProvider error")
	bobProviderKey := keysMap[*descriptor.MixKeys[epoch]]

	t.Logf("ALICE Provider Key: %x", aliceProviderKey.Bytes())
	bobsCiphertext, err := decryptSphinxLayers(t, require, sendPacket.SphinxPacket, aliceProviderKey, bobProviderKey, keysMap, nrHops)
	require.NoError(err, "handler decrypt sphinx layers failure")
	//bobSurb := bobsCiphertext[:556] // used for reply SURB ACK
	b, _, err := bobBlockHandler.Decrypt(bobsCiphertext[hdrLength:])
	require.NoError(err, "handler decrypt failure")
	t.Logf("block: %s", string(b.Block))

	// Bob sends message to Alice
	aliceID := [sphinxconstants.RecipientIDLength]byte{}
	copy(aliceID[:], "alice")
	toAliceBlock := block.Block{
		TotalBlocks: 1,
		Block:       []byte("Alice, I have the documents you requested."),
	}
	bobEgressBlock := storage.EgressBlock{
		Sender:            "bob@nsa.gov",
		SenderProvider:    "nsa.gov",
		Recipient:         "alice@acme.com",
		RecipientProvider: "acme.com",
		RecipientID:       aliceID,
		Block:             toAliceBlock,
	}
	blockID, err = bobStore.PutEgressBlock(&bobEgressBlock)
	rtt, err = bobSender.Send(blockID, &bobEgressBlock)
	require.NoError(err, "Send failure")
	t.Logf("Bob send rtt %s", rtt)
}
