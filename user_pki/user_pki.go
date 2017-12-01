// user_pki.go - client user key pki
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

// Package user_pki provides client end to end user identity PKI
package user_pki

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/katzenpost/core/crypto/ecdh"
)

// UserPKI is an interface that represents
// the user end to end key retrieval mechanism
type UserPKI interface {
	GetKey(email string) (*ecdh.PublicKey, error)
}

type User struct {
	Email string
	Key   string
}

type JsonFileUserPKI struct {
	UserMap map[string]*ecdh.PublicKey
}

func (j *JsonFileUserPKI) GetKey(email string) (*ecdh.PublicKey, error) {
	value, ok := j.UserMap[strings.ToLower(email)]
	if !ok {
		return nil, errors.New("json user pki email lookup failed")
	}
	return value, nil
}

func UserPKIFromJsonFile(filePath string) (*JsonFileUserPKI, error) {
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var users []User
	err = json.Unmarshal(fileData, &users)
	if err != nil {
		return nil, err
	}
	userKeyMap := make(map[string]*ecdh.PublicKey)
	for i := 0; i < len(users); i++ {
		if len(users[i].Email) == 0 {
			return nil, errors.New("nil user name error")
		}
		_, ok := userKeyMap[users[i].Email]
		if ok {
			return nil, errors.New("user name already in PKI map")
		}
		keyRaw, err := base64.StdEncoding.DecodeString(users[i].Key)
		if err != nil {
			return nil, errors.New("failed to base64 decode user key")
		}
		key := ecdh.PublicKey{}
		err = key.FromBytes(keyRaw)
		if err != nil {
			return nil, errors.New("failed to get key from given bytes")
		}
		userKeyMap[users[i].Email] = &key
	}
	pki := JsonFileUserPKI{
		UserMap: userKeyMap,
	}
	return &pki, nil
}
