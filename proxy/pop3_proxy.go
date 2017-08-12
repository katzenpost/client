// pop3.go - POP3 + mixnet proxy server.
// Copyright (C) 2017  David Stainton.
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

// Package proxy provides mixnet client proxies
package proxy

import (
	"bytes"
	"fmt"
	"net"

	"github.com/katzenpost/client/pop3"
)

const (
	testUser = "alice"
	testPass = "teatime475"
)

type Pop3BackendSession struct{}

func (s Pop3BackendSession) Messages() ([][]byte, error) {
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
	}
	return messages, nil
}

func (s Pop3BackendSession) DeleteMessages([]int) error {
	return nil
}

func (s Pop3BackendSession) Close() {
}

type Pop3Backend struct {
}

func (b Pop3Backend) NewSession(user, pass []byte) (pop3.BackendSession, error) {
	if !bytes.Equal(user, []byte(testUser)) || !bytes.Equal(pass, []byte(testPass)) {
		return nil, fmt.Errorf("invalid user/password: '%s'/'%s'", user, pass)
	}
	return Pop3BackendSession{}, nil
}

type Pop3Proxy struct {
}

func NewPop3Proxy() *Pop3Proxy {
	p := Pop3Proxy{}
	return &p
}

func (p *Pop3Proxy) handleConnection(conn net.Conn) error {
	defer conn.Close()
	backend := Pop3Backend{}
	pop3Session := pop3.NewSession(conn, backend)
	pop3Session.Serve()
	return nil
}
