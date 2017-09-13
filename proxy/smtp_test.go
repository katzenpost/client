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
	"net"
	"net/textproto"
	"sync"
	"testing"

	"github.com/katzenpost/client/config"
	"github.com/katzenpost/client/path_selection"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
)

func TestSubmitProxy(t *testing.T) {
	require := require.New(t)

	aliceEmail := "alice@acme.com"
	alicePool, aliceStore, alicePrivKey, aliceBlockHandler := makeUser(require, aliceEmail)

	accounts := config.AccountsMap(map[string]*ecdh.PrivateKey{
		"alice@acme.com": alicePrivKey,
	})

	bobEmail := "bob@nsa.gov"
	//bobPool, bobStore, bobPrivKey, bobBlockHandler := makeUser(require, bobEmail)
	_, _, bobPrivKey, _ := makeUser(require, bobEmail)

	userPKI := MockUserPKI{
		userMap: map[string]*ecdh.PublicKey{
			aliceEmail: alicePrivKey.PublicKey(),
			bobEmail:   bobPrivKey.PublicKey(),
		},
	}

	mixPKI, _, _ := newMixPKI(require)
	nrHops := 5
	lambda := float64(.123)
	routeFactory := path_selection.New(mixPKI, nrHops, lambda)

	aliceSender, err := NewSender(aliceEmail, alicePool, aliceStore, routeFactory, userPKI, aliceBlockHandler)
	require.NoError(err, "NewSender failure")
	senders := map[string]*Sender{
		aliceEmail: aliceSender,
	}
	sendScheduler := NewSendScheduler(senders)

	submitProxy := NewSmtpProxy(&accounts, rand.Reader, userPKI, aliceStore, alicePool, routeFactory, sendScheduler)
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

		//l, err = c.ReadLine()
		//require.NoError(err, "failed reading")
		//t.Logf("S->C: '%s'", l)
	}()

	wg.Wait()
}
