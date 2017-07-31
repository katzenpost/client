// pop3_test.go - Tests Yawning's Pop3
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

// Package pop3 implements a minimal POP3 server, mostly intended to be ran
// over the loopback interface.
package pop3

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type TestAddr struct {
	NetworkString string
	AddrString    string
}

func (a TestAddr) Network() string {
	return a.NetworkString
}

func (a TestAddr) String() string {
	return a.AddrString
}

type End struct {
	Reader *io.PipeReader
	Writer *io.PipeWriter
}

func (c End) Close() error {
	if err := c.Writer.Close(); err != nil {
		return err
	}
	if err := c.Reader.Close(); err != nil {
		return err
	}
	return nil
}

func (e End) Read(data []byte) (n int, err error)  { return e.Reader.Read(data) }
func (e End) Write(data []byte) (n int, err error) { return e.Writer.Write(data) }

func (e End) LocalAddr() net.Addr {
	return TestAddr{
		NetworkString: "tcp",
		AddrString:    "127.0.0.1:123",
	}
}

func (e End) RemoteAddr() net.Addr {
	return TestAddr{
		NetworkString: "tcp",
		AddrString:    "127.0.0.1:567",
	}
}

func (e End) SetDeadline(t time.Time) error      { return nil }
func (e End) SetReadDeadline(t time.Time) error  { return nil }
func (e End) SetWriteDeadline(t time.Time) error { return nil }

type TestConn struct {
	Server *End
	Client *End
}

func NewConn() *TestConn {
	serverRead, clientWrite := io.Pipe()
	clientRead, serverWrite := io.Pipe()

	return &TestConn{
		Server: &End{
			Reader: serverRead,
			Writer: serverWrite,
		},
		Client: &End{
			Reader: clientRead,
			Writer: clientWrite,
		},
	}
}

func (c *TestConn) Close() error {
	if err := c.Server.Close(); err != nil {
		return err
	}
	if err := c.Client.Close(); err != nil {
		return err
	}
	return nil
}

type TestListener struct {
	connections chan net.Conn
	state       chan bool
}

func NewTestListener() TestListener {
	listener := TestListener{
		connections: make(chan net.Conn, 0),
		state:       make(chan bool, 0),
	}
	return listener
}

func (l TestListener) Accept() (net.Conn, error) {
	fmt.Println("Accept")
	select {
	case newConnection := <-l.connections:
		return newConnection, nil
	case <-l.state:
		return nil, errors.New("Listener closed")
	}
}

func (l *TestListener) Dial(network, addr string) (net.Conn, error) {
	select {
	case <-l.state:
		return nil, errors.New("Listener closed")
	default:
	}
	serverSide, clientSide := net.Pipe()
	l.connections <- serverSide
	return clientSide, nil
}

func (l TestListener) Close() error {
	return nil
}

func (l TestListener) Addr() net.Addr {
	return TestAddr{
		NetworkString: "pipe",
		AddrString:    "pipe",
	}
}

type TestBackendSession struct {
}

func (s TestBackendSession) Messages() ([][]byte, error) {
	messages := [][]byte{
		[]byte(string(`Return-Path: 
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
`)),
	}
	return messages, nil
}

func (s TestBackendSession) DeleteMessages([]int) error {
	return nil
}

func (s TestBackendSession) Close() {
}

type TestBackend struct {
}

func (b TestBackend) NewSession(user, pass []byte) (BackendSession, error) {
	fmt.Println("NewSession:", "user:", user, "pass:", pass)
	return TestBackendSession{}, nil
}

func TestPop3(t *testing.T) {
	assert := assert.New(t)

	testBackend := TestBackend{}
	server := Server{
		b: testBackend,
	}
	//server.Start()
	//defer server.Stop()

	//clientConn, err := testListener.Dial("tcp", "test123")
	clientConn, _ := net.Pipe()
	//session := newSession(&server, clientConn)

	rcvBuf := make([]byte, 666)
	count, err := clientConn.Read(rcvBuf)
	assert.NoError(err, fmt.Sprintf("read fail: read count %d", count))

	fmt.Println("received server greeting: ", string(rcvBuf))

	_, err = clientConn.Write([]byte(string("user alice\n")))
	assert.NoError(err, "write fail")
	count, err = clientConn.Read(rcvBuf)
	assert.NoError(err, fmt.Sprintf("read fail: read count %d", count))
	fmt.Println("server response: ", string(rcvBuf))

	_, err = clientConn.Write([]byte(string("pass teatime476\n")))
	assert.NoError(err, "write fail")
	count, err = clientConn.Read(rcvBuf)
	assert.NoError(err, fmt.Sprintf("read fail: read count %d", count))
	fmt.Println("server response: ", string(rcvBuf))

	_, err = clientConn.Write([]byte(string("list\n")))
	assert.NoError(err, "write fail")
	clientReader := bufio.NewReader(clientConn)
	message, err := clientReader.ReadString('.')
	assert.NoError(err, "ReadString fail")
	fmt.Println("message", message)
}
