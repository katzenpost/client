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
	"context"
	"crypto/subtle"

	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/wire"
	"github.com/op/go-logging"
)

// ProviderAuthenticator implements the PeerAuthenticator interface
// which is used to authenticate remote peers (in this case a provider)
// based on the authenticated key exchange
// as specified in core/wire/session.go
type ProviderAuthenticator struct {
	mixPKI pki.Client
	log    *logging.Logger
}

// IsPeerValid authenticates the remote peer's credentials, returning true
// iff the peer is valid.
func (a ProviderAuthenticator) IsPeerValid(peer *wire.PeerCredentials) bool {
	a.log.Debugf("IsPeerValid: %s", string(peer.AdditionalData))
	ctx := context.TODO() // XXX set a deadline
	epoch, _, _ := epochtime.Now()
	doc, err := a.mixPKI.Get(ctx, epoch)
	if err != nil {
		// XXX log the error
		a.log.Errorf("Failed to retreive PKI document: %v", err)
		return false
	}
	providerName := string(peer.AdditionalData)
	for _, provider := range doc.Providers {
		if providerName == provider.Name {
			if subtle.ConstantTimeCompare(provider.LinkKey.Bytes(), peer.PublicKey.Bytes()) == 1 {
				return true
			} else {
				return false
			}
		}
	}
	return false
}

// New returns a new ProviderAuthenticator
func New(logBackend *log.Backend, mixPKI pki.Client) *ProviderAuthenticator {
	a := ProviderAuthenticator{
		mixPKI: mixPKI,
		log:    logBackend.GetLogger("ProviderAuthenticator"),
	}
	return &a
}
