// smtp_test.go - tests for client smtp submit proxy
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
	"io/ioutil"
	"net"
	"net/textproto"
	"sync"
	"testing"

	"github.com/katzenpost/client/config"
	"github.com/katzenpost/client/path_selection"
	coreconstants "github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/wire/commands"
	"github.com/stretchr/testify/require"
)

func TestEndToEndProxy(t *testing.T) {
	require := require.New(t)

	const (
		hdrLength    = coreconstants.SphinxPlaintextHeaderLength + sphinx.SURBLength
		flagsPadding = 0
		flagsSURB    = 1
		reserved     = 0
	)

	aliceEmail := "alice@acme.com"
	alicePool, aliceStore, alicePrivKey, aliceBlockHandler := makeUser(require, aliceEmail)

	accounts := config.AccountsMap(map[string]*ecdh.PrivateKey{
		"alice@acme.com": alicePrivKey,
	})

	bobEmail := "bob@nsa.gov"
	bobPool, bobStore, bobPrivKey, bobBlockHandler := makeUser(require, bobEmail)

	userPKI := MockUserPKI{
		userMap: map[string]*ecdh.PublicKey{
			aliceEmail: alicePrivKey.PublicKey(),
			bobEmail:   bobPrivKey.PublicKey(),
		},
	}

	mixPKI, keysMap := newMixPKI(require)

	nrHops := 5
	lambda := float64(.123)
	maxDelay := uint64(666)
	routeFactory := path_selection.New(mixPKI, nrHops, lambda, maxDelay)
	logBackend, err := log.New("e2e_test", "DEBUG", false)
	require.NoError(err, "failed creating log backend")
	aliceSender, err := NewSender(logBackend, aliceEmail, alicePool, aliceStore, routeFactory, userPKI, aliceBlockHandler)
	require.NoError(err, "NewSender failure")
	senders := map[string]*Sender{
		aliceEmail: aliceSender,
	}
	sendScheduler := NewSendScheduler(logBackend, senders)

	submitProxy := NewSmtpProxy(logBackend, &accounts, rand.Reader, userPKI, aliceStore, alicePool, routeFactory, sendScheduler)
	aliceServerConn, aliceClientConn := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer aliceServerConn.Close()
		defer aliceClientConn.Close()

		err = submitProxy.HandleSMTPSubmission(aliceServerConn)
		require.NoError(err, "HandleSMTPSubmission failure")
	}()

	go func() {
		defer wg.Done()
		defer aliceServerConn.Close()
		defer aliceClientConn.Close()

		c := textproto.NewConn(aliceClientConn)
		defer c.Close()

		// Server speaks first, expecting a banner.
		l, err := c.ReadLine()
		require.NoError(err, "failed reading banner")
		t.Logf("S->C: '%s'", l)

		err = c.PrintfLine("helo localhost")
		require.NoError(err, "failed sending")

		l, err = c.ReadLine()
		require.NoError(err, "failed reading")
		t.Logf("S->C: '%s'", l)

		err = c.PrintfLine("mail from:<%s>", aliceEmail)
		require.NoError(err, "failed sending mail from:")

		l, err = c.ReadLine()
		require.NoError(err, "failed reading")
		t.Logf("S->C: '%s'", l)

		err = c.PrintfLine("rcpt to:<%s>", bobEmail)
		require.NoError(err, "failed sending")

		l, err = c.ReadLine()
		require.NoError(err, "failed reading")
		t.Logf("S->C: '%s'", l)

		err = c.PrintfLine("DATA")
		require.NoError(err, "failed sending")

		l, err = c.ReadLine()
		require.NoError(err, "failed reading")
		t.Logf("S->C: '%s'", l)

		err = c.PrintfLine("Subject: hello\r\n")
		require.NoError(err, "failed sending")
		err = c.PrintfLine("super short message because byte stuffing is hard")
		require.NoError(err, "failed sending")
		err = c.PrintfLine("\r\n.\r\n")
		require.NoError(err, "failed sending")
	}()

	wg.Wait()

	// decrypt Alice's captured sphinx packet
	aliceSession := alicePool.Sessions["alice@acme.com"]
	mockAliceSession, ok := aliceSession.(*MockSession)
	require.True(ok, "failed to get MockSession")
	sendPacket, ok := mockAliceSession.sentCommands[0].(*commands.SendPacket)
	require.True(ok, "failed to get SendPacket command")

	epoch, _, _ := epochtime.Now()
	ctx := context.TODO() // XXX
	doc, err := mixPKI.Get(ctx, epoch)
	require.NoError(err, "pki Get failure")

	descriptor, err := doc.GetProvider("acme.com")
	require.NoError(err, "pki GetProvider error")
	aliceProviderKey := keysMap[*descriptor.MixKeys[epoch]]

	descriptor, err = doc.GetProvider("nsa.gov")
	require.NoError(err, "pki GetProvider error")
	bobProviderKey := keysMap[*descriptor.MixKeys[epoch]]

	t.Logf("ALICE Provider Key: %x", aliceProviderKey.Bytes())
	bobsCiphertext, err := decryptSphinxLayers(t, require, sendPacket.SphinxPacket, aliceProviderKey, bobProviderKey, keysMap, nrHops)
	require.NoError(err, "decrypt sphinx layers failure")
	require.Equal(len(bobsCiphertext), coreconstants.ForwardPayloadLength, "ciphertext len mismatch")
	blockCiphertext := bobsCiphertext[hdrLength:]
	b, _, err := bobBlockHandler.Decrypt(blockCiphertext)
	require.NoError(err, "handler decrypt failure")
	t.Logf("block: %s", string(b.Block))

	bobStore.CreateAccountBuckets([]string{bobEmail})
	bobFetcher := Fetcher{
		log:      logBackend.GetLogger("bob_fetcher"),
		Identity: bobEmail,
		pool:     bobPool,
		store:    bobStore,
		handler:  bobBlockHandler,
	}

	bobSession := bobPool.Sessions["bob@nsa.gov"]
	mockBobSession, ok := bobSession.(*MockSession)
	require.True(ok, "failed to get MockSession")
	msgCmd := commands.Message{
		QueueSizeHint: 0,
		Sequence:      0,
		Payload:       bobsCiphertext[hdrLength:],
	}
	mockBobSession.recvCommands = append(mockBobSession.recvCommands, msgCmd)

	queueHintSize, err := bobFetcher.Fetch()
	require.NoError(err, "Fetch failure")
	t.Logf("queueHintSize %d", queueHintSize)

	pop3Service := NewPop3Service(bobStore)
	bobPop3ServerConn, bobPop3ClientConn := net.Pipe()

	wg.Add(2)

	go func() {
		defer wg.Done()
		defer bobPop3ServerConn.Close()
		defer bobPop3ClientConn.Close()

		err := pop3Service.HandleConnection(bobPop3ServerConn)
		require.NoError(err, "pop3 service HandleConnection failure")
	}()

	go func() {
		defer wg.Done()
		defer bobPop3ServerConn.Close()
		defer bobPop3ClientConn.Close()

		c := textproto.NewConn(bobPop3ClientConn)
		defer c.Close()

		// Server speaks first, expecting a banner.
		l, err := c.ReadLine()
		require.NoError(err, "failed reading banner")
		t.Logf("S->C: '%s'", l)

		// USER
		err = c.PrintfLine("USER %s", bobEmail)
		require.NoError(err, "failed sending USER")
		l, err = c.ReadLine()
		require.NoError(err, "failed reading USER response")
		t.Logf("S->C: '%s'", l)

		// PASS
		bobsPassword := "any_password"
		err = c.PrintfLine("PASS %s", bobsPassword)
		require.NoError(err, "failed sending PASS")
		l, err = c.ReadLine()
		require.NoError(err, "failed reading PASS response")
		t.Logf("S->C: '%s'", l)

		// CAPA
		err = c.PrintfLine("CAPA")
		require.NoError(err, "failed sending CAPA")
		dr := c.DotReader()
		bl, err := ioutil.ReadAll(dr)
		require.NoError(err, "failed reading CAPA response")
		t.Logf("S->C: '%s'", bl)

		// LIST
		err = c.PrintfLine("LIST")
		require.NoError(err, "failed sending LIST")
		dr = c.DotReader()
		bl, err = ioutil.ReadAll(dr)
		require.NoError(err, "failed reading LIST response")
		t.Logf("S->C: '%s'", bl)

		// RETR
		err = c.PrintfLine("RETR 1")
		require.NoError(err, "failed sending RETR")
		dr = c.DotReader()
		bl, err = ioutil.ReadAll(dr)
		require.NoError(err, "failed reading RETR response")
		t.Logf("S->C: '%s'", bl)

	}()

	wg.Wait()
}
