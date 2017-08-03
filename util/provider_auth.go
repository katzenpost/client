// wire_peer_auth.go - client wire authentication for peers
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
	"crypto/subtle"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/wire"
)

type providerAuthenticator struct {
	config  *Config
	keysMap map[[255]byte]*ecdh.PublicKey
}

func newProviderAuthenticator(config *Config) (*providerAuthenticator, error) {
	keysMap, err := config.GetProviderPinnedKeys()
	if err != nil {
		return nil, err
	}
	authenticator := providerAuthenticator{
		keysMap: keysMap,
	}
	return &authenticator, nil
}

// IsPeerValid authenticates the remote peer's credentials, returning true
// iff the peer is valid.
func (a *providerAuthenticator) IsPeerValid(peer *wire.PeerCredentials) bool {
	nameField := [255]byte{}
	copy(nameField[:], peer.AdditionalData)
	_, ok := a.keysMap[nameField]
	if !ok {
		return false
	}
	if subtle.ConstantTimeCompare(a.keysMap[nameField].Bytes(), peer.PublicKey.Bytes()) != 1 {
		return false
	}
	return true
}
