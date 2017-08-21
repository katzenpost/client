// pop3_proxy_test.go - pop3 proxy tests
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
	"io/ioutil"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/boltdb/bolt"
	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/storage/ingress"
	"github.com/stretchr/testify/require"
)

const (
	testUser = "alice"
	testPass = "teatime475"
)

func setupPop3Db(dbFile, bucketName string) error {
	messages := [][]byte{
		[]byte(`Return-Path: 
X-Original-To: mailtest@normal.gateway.name
Delivered-To: mailtest@normal.gateway.name
Received: from normal.mailhost.name (node18 [192.168.2.38])
        by normal.gateway.name (Postfix) with ESMTP id DEADBEEFCA
        for ; Tue, 12 Apr 2017 22:24:53 -0400 (EDT)
Received: from me?here.com (unknown [192.168.2.250])
        by normal.mailhost.name (Postfix) with SMTP id AAAAAAAAAA
        for ; Tue, 12 Apr 2017 22:24:03 -0400 (EDT)
To: fro@hill
From: pp@pp
Subject: Forged e-mail
Message-Id: <20050413022403.4653B14112@normal.mailhost.name>
Date: Tue, 12 Apr 2005 22:24:03 -0400 (EDT)

lossy packet switching network
`),
		[]byte(`"The time has come," the Walrus said,
"To talk of many things:
Of shoes-and ships-and sealing-wax-
Of cabbages-and kings-
And why the sea is boiling hot-
And whether pigs have wings."

.
..
... Byte-stuffing is hard, let's go shopping!
..
.
`),
		[]byte(`hello alice, this is bob, from the mix net.
did you receive the package?
`),
	}

	db, err := bolt.Open(dbFile, 0600, &bolt.Options{Timeout: constants.DatabaseConnectTimeout})
	if err != nil {
		return err
	}
	transaction := func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		for i, message := range messages {
			err := bucket.Put([]byte(strconv.Itoa(i)), message)
			if err != nil {
				return err
			}
		}
		return nil
	}

	err = db.Update(transaction)
	if err != nil {
		return err
	}
	err = db.Close()
	return err
}

func TestPop3Basics(t *testing.T) {
	require := require.New(t)

	dbFile, err := ioutil.TempFile("", "pop3_db_test")
	require.NoError(err, "unexpected TempFile error")
	defer func() {
		err := os.Remove(dbFile.Name())
		require.NoError(err, "unexpected os.Remove error")
	}()

	err = setupPop3Db(dbFile.Name(), testUser)
	require.NoError(err, "unexpected setupPop3Db error")

	store, err := ingress.New(dbFile.Name())
	require.NoError(err, "unexpected ingress.New error")
	pop3 := NewPop3Service(store)

	serverConn, clientConn := net.Pipe()
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()
		defer serverConn.Close()
		defer clientConn.Close()

		err = pop3.HandleConnection(serverConn)
		require.NoError(err, "unexpected HandleConnection error")
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer serverConn.Close()

		c := textproto.NewConn(clientConn)
		defer c.Close()

		// Server speaks first, expecting a banner.
		l, err := c.ReadLine()
		require.NoError(err, "failed reading banner")
		t.Logf("S->C: '%s'", l)

		// USER
		err = c.PrintfLine("USER %s", testUser)
		require.NoError(err, "failed sending USER")
		l, err = c.ReadLine()
		require.NoError(err, "failed reading USER response")
		t.Logf("S->C: '%s'", l)

		// PASS
		err = c.PrintfLine("PASS %s", testPass)
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

		// RETR
		err = c.PrintfLine("RETR 2")
		require.NoError(err, "failed sending RETR")
		dr = c.DotReader()
		bl, err = ioutil.ReadAll(dr)
		require.NoError(err, "failed reading RETR response")
		t.Logf("S->C: '%s'", bl)

		// UIDL
		err = c.PrintfLine("UIDL")
		require.NoError(err, "failed sending UIDL")
		dr = c.DotReader()
		bl, err = ioutil.ReadAll(dr)
		require.NoError(err, "failed reading UIDL response")
		t.Logf("S->C: '%s'", bl)

		// DELE
		err = c.PrintfLine("DELE 1")
		require.NoError(err, "failed sending DELE")
		l, err = c.ReadLine()
		require.NoError(err, "failed reading DELE response")
		t.Logf("S->C: '%s'", l)

		// UIDL
		err = c.PrintfLine("UIDL")
		require.NoError(err, "failed sending UIDL")
		dr = c.DotReader()
		bl, err = ioutil.ReadAll(dr)
		require.NoError(err, "failed reading UIDL response")
		t.Logf("S->C: '%s'", bl)

		// RETR
		err = c.PrintfLine("RETR 2")
		require.NoError(err, "failed sending RETR")
		dr = c.DotReader()
		bl, err = ioutil.ReadAll(dr)
		require.NoError(err, "failed reading RETR response")
		t.Logf("S->C: '%s'", bl)

		// QUIT
		err = c.PrintfLine("QUIT")
		require.NoError(err, "failed sending QUIT")
		l, err = c.ReadLine()
		require.NoError(err, "failed reading QUIT response")
		t.Logf("S->C: '%s'", l)
	}()

	wg.Wait()

	// after old connections are done make a new ones
	serverConn, clientConn = net.Pipe()

	wg.Add(2)

	go func() {
		defer wg.Done()
		defer serverConn.Close()
		defer clientConn.Close()

		err = pop3.HandleConnection(serverConn)
		require.NoError(err, "unexpected HandleConnection error")
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer serverConn.Close()

		c := textproto.NewConn(clientConn)
		defer c.Close()

		// Server speaks first, expecting a banner.
		l, err := c.ReadLine()
		require.NoError(err, "failed reading banner")
		t.Logf("S->C: '%s'", l)

		// USER
		err = c.PrintfLine("USER %s", testUser)
		require.NoError(err, "failed sending USER")
		l, err = c.ReadLine()
		require.NoError(err, "failed reading USER response")
		t.Logf("S->C: '%s'", l)

		// PASS
		err = c.PrintfLine("PASS %s", testPass)
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
		err = c.PrintfLine("RETR 2")
		require.NoError(err, "failed sending RETR")
		dr = c.DotReader()
		bl, err = ioutil.ReadAll(dr)
		require.NoError(err, "failed reading RETR response")
		t.Logf("S->C: '%s'", bl)

	}()

	wg.Wait()

}
