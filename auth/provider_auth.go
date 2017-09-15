// provider_auth.go - client wire authentication for peers
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

// Package provides mixnet Provider authentication
package auth

import (
	"crypto/subtle"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/wire"
)

// ProviderAuthenticator implements the PeerAuthenticator interface
// which is used to authenticate remote peers (in this case a provider)
// based on the authenticated key exchange
// as specified in core/wire/session.go
type ProviderAuthenticator map[[255]byte]*ecdh.PublicKey

// IsPeerValid authenticates the remote peer's credentials, returning true
// iff the peer is valid.
func (a *ProviderAuthenticator) IsPeerValid(peer *wire.PeerCredentials) bool {
	nameField := [255]byte{}
	copy(nameField[:], peer.AdditionalData)
	_, ok := a[nameField]
	if !ok {
		return false
	}
	if subtle.ConstantTimeCompare(a[nameField].Bytes(), peer.PublicKey.Bytes()) != 1 {
		return false
	}
	return true
}
