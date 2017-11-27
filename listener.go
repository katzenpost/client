// client.go - Katzenpost client.
// Copyright (C) 2017  David Stainton, Yawning Angel
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

// Package client provides the Katzenpost client.
package client

import (
	"container/list"
	"net"
	"sync"
	"time"

	"github.com/katzenpost/core/log"
	"github.com/op/go-logging"
)

const keepAliveInterval = 3 * time.Minute

type listener struct {
	sync.WaitGroup
	sync.Mutex

	l   net.Listener
	log *logging.Logger

	connectionCallback func(net.Conn) error
	conns              *list.List

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup
}

func (l *listener) halt() {
	// Close the listener, wait for worker() to return.
	l.l.Close()
	l.Wait()

	// Close all connections belonging to the listener.
	close(l.closeAllCh)
	l.closeAllWg.Wait()
}

func (l *listener) worker() {
	addr := l.l.Addr()
	l.log.Noticef("Listening on: %v", addr)
	defer func() {
		l.log.Noticef("Stopping listening on: %v", addr)
		l.l.Close() // Usually redundant, but harmless.
		l.Done()
	}()
	for {
		conn, err := l.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				l.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}

		tcpConn := conn.(*net.TCPConn)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(keepAliveInterval)

		l.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())

		go l.onNewConn(conn)
	}

	// NOTREACHED
}

func (l *listener) onNewConn(conn net.Conn) {
	l.closeAllWg.Add(1)
	l.Lock()
	defer l.Unlock()
	l.conns.PushFront(conn)
	if err := l.connectionCallback(conn); err != nil {
		l.log.Error(err)
	}
	l.closeAllWg.Done()
}

func newListener(addr string, connectionCallback func(net.Conn) error, logBackend *log.Backend) (*listener, error) {
	var err error

	l := new(listener)
	l.connectionCallback = connectionCallback
	l.log = logBackend.GetLogger("listener")
	l.conns = list.New()
	l.closeAllCh = make(chan interface{})
	l.Add(1)

	l.l, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	go l.worker()
	return l, nil
}
