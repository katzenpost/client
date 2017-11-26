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
	"context"
	"net"
	"sync"

	"github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/wire"
)

// SessionPool maps sender email string to sender identity
// wire protocol session with the Provider
type SessionPool struct {
	sync.Mutex

	Sessions     map[string]wire.SessionInterface
	SessionLocks map[string]*sync.Mutex

	accountsKey           *config.AccountsMap
	config                *config.Config
	providerAuthenticator wire.PeerAuthenticator
	mixPKI                pki.Client
}

// New creates a new SessionPool
func New(accountsKey *config.AccountsMap, config *config.Config, providerAuthenticator wire.PeerAuthenticator, mixPKI pki.Client) (*SessionPool, error) {
	s := SessionPool{
		Sessions:              make(map[string]wire.SessionInterface),
		SessionLocks:          make(map[string]*sync.Mutex),
		accountsKey:           accountsKey,
		config:                config,
		providerAuthenticator: providerAuthenticator,
		mixPKI:                mixPKI,
	}
	return &s, nil
}

// Get returns a session and a mutex or an error using a given identity
// string which is of the form "alice@provider-123", resembling an email address
func (s *SessionPool) Get(identity string) (wire.SessionInterface, *sync.Mutex, error) {
	v, ok := s.Sessions[identity]
	if ok {
		return v, s.SessionLocks[identity], nil
	}

	privateKey, err := s.accountsKey.GetIdentityKey(identity)
	if err != nil {
		return nil, nil, err
	}
	name, provider, err := config.SplitEmail(identity)
	if err != nil {
		return nil, nil, err
	}
	sessionConfig := wire.SessionConfig{
		Authenticator:     s.providerAuthenticator,
		AdditionalData:    []byte(name),
		AuthenticationKey: privateKey,
		RandomReader:      rand.Reader,
	}
	session, err := wire.NewSession(&sessionConfig, true)
	if err != nil {
		return nil, nil, err
	}
	epoch, _, _ := epochtime.Now()
	ctx := context.TODO() // XXX fix me
	doc, err := s.mixPKI.Get(ctx, epoch)
	if err != nil {
		return nil, nil, err
	}
	providerDesc, err := doc.GetProvider(provider)
	if err != nil {
		return nil, nil, err
	}
	// XXX TODO: retry with other addresses if available
	conn, err := net.Dial("tcp", providerDesc.Addresses[0])
	if err != nil {
		return nil, nil, err
	}
	err = session.Initialize(conn)
	if err != nil {
		return nil, nil, err
	}
	s.Lock()
	defer s.Unlock()
	s.Sessions[identity] = session
	s.SessionLocks[identity] = new(sync.Mutex)
	return s.Sessions[identity], s.SessionLocks[identity], nil
}

func (s *SessionPool) Identities() []string {
	ids := []string{}
	for id, _ := range s.Sessions {
		ids = append(ids, id)
	}
	return ids
}
