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

// Package util provides client utilities
package util

import (
	"errors"
	"fmt"
	"net"

	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/wire"
)

type SessionPool struct {
	sessions map[string]*wire.Session
}

func NewSessionPool() *SessionPool {
	s := SessionPool{
		sessions: make(map[string]*wire.Session),
	}
	return &s
}

func FromAccounts(accounts []Account, config *Config, keysDir, passphrase string, mixPKI pki.Client) (*SessionPool, error) {
	pool := NewSessionPool()
	providerAuthenticator, err := newProviderAuthenticator(config)
	if err != nil {
		return nil, err
	}
	for _, account := range accounts {
		privateKey, err := config.GetAccountKey(account, keysDir, passphrase)
		if err != nil {
			return nil, err
		}
		sessionConfig := wire.SessionConfig{
			Authenticator:     providerAuthenticator,
			AdditionalData:    []byte(account.Name),
			AuthenticationKey: privateKey,
			RandomReader:      rand.Reader,
		}
		email := fmt.Sprintf("%s@%s", account.Name, account.Provider)
		session, err := wire.NewSession(&sessionConfig, true)
		if err != nil {
			return nil, err
		}
		providerDesc, err := mixPKI.GetProviderDescriptor(account.Provider)
		if err != nil {
			return nil, err
		}
		log.Debugf("connecting to Provider %s on ip %s port %d", providerDesc.Name, providerDesc.Ipv4Address, providerDesc.TcpPort)
		log.Debugf("pool %v email %v session %v", pool, email, session)
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", providerDesc.Ipv4Address, providerDesc.TcpPort))
		if err != nil {
			return nil, err
		}
		err = session.Initialize(conn)
		if err != nil {
			return nil, err
		}
		pool.Add(email, session)
	}
	return pool, nil
}

func (s *SessionPool) Add(identity string, session *wire.Session) {
	s.sessions[identity] = session
}

func (s *SessionPool) Get(identity string) (*wire.Session, error) {
	v, ok := s.sessions[identity]
	if !ok {
		return nil, errors.New("wire protocol session pool key not found")
	}
	return v, nil
}
