// pool.go - session pool for mixnet clients
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

// Package provides wire protocol session pool API
package session_pool

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/wire"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("mixclient")

// SessionPool maps sender email string to sender identity
// wire protocol session with the Provider
type SessionPool struct {
	sessions map[string]*wire.Session
	locks    map[string]*sync.Mutex
}

// New creates a new SessionPool
func New(accounts *config.AccountsMap, config *config.Config, providerAuthenticator wire.PeerAuthenticator, mixPKI pki.Client) (*SessionPool, error) {
	s := SessionPool{
		sessions: make(map[string]*wire.Session),
	}
	for _, acct := range config.Account {
		email := fmt.Sprintf("%s@%s", acct.Name, acct.Provider)
		privateKey, err := accounts.GetIdentityKey(email)
		if err != nil {
			return nil, err
		}
		sessionConfig := wire.SessionConfig{
			Authenticator:     providerAuthenticator,
			AdditionalData:    []byte(acct.Name),
			AuthenticationKey: privateKey,
			RandomReader:      rand.Reader,
		}
		session, err := wire.NewSession(&sessionConfig, true)
		if err != nil {
			return nil, err
		}
		providerDesc, err := mixPKI.GetProviderDescriptor(acct.Provider)
		if err != nil {
			return nil, err
		}
		// XXX hard code "tcp" here?
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", providerDesc.Ipv4Address, providerDesc.TcpPort))
		if err != nil {
			return nil, err
		}
		err = session.Initialize(conn)
		if err != nil {
			return nil, err
		}
		s.sessions[email] = session
	}
	return &s, nil
}

func (s *SessionPool) Add(identity string, session *wire.Session) {
	s.sessions[identity] = session
	s.locks[identity] = &sync.Mutex{}
}

func (s *SessionPool) Get(identity string) (*wire.Session, *sync.Mutex, error) {
	v, ok := s.sessions[identity]
	if !ok {
		return nil, nil, errors.New("wire protocol session pool key not found")
	}
	return v, s.locks[identity], nil
}

func (s *SessionPool) Identities() []string {
	ids := []string{}
	for id, _ := range s.sessions {
		ids = append(ids, id)
	}
	return ids
}
