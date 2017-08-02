// daemon.go - client management of configurations and services
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

type peerAuthenticator struct {
	keysMap map[[255]byte]*ecdh.PublicKey
}

func newPeerAuthenticator(configFile, passphrase, keysDir string) (*peerAuthenticator, error) {
	tree, err := loadConfigTree(configFile)
	if err != nil {
		return nil, err
	}
	pinnings := tree.Get("ProviderPinning").([]*toml.Tree)
	keysMap := make(map[[255]byte]*ecdh.PublicKey)
	for i := 0; i < len(pinnings); i++ {
		name := pinnings[i].Get("name").([]byte)
		pemPayload, err := ioutil.ReadFile(pinnings[i].Get("certificate").(string))
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pemPayload)
		if block == nil {
			return nil, err
		}
		publicKey := new(ecdh.PublicKey)
		publicKey.FromBytes(block.Bytes)
		nameField := [255]byte{}
		copy(nameField[:], name)
		keysMap[nameField] = publicKey
	}
	authenticator := peerAuthenticator{
		keysMap: keysMap,
	}
	return &authenticator, nil
}

// IsPeerValid authenticates the remote peer's credentials, returning true
// iff the peer is valid.
func (a *peerAuthenticator) IsPeerValid(peer *wire.PeerCredentials) bool {
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
