// config.go - mixnet client configuration
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
	"io/ioutil"

	"github.com/pelletier/go-toml"
)

type Account struct {
	Name     string
	Provider string
}

type ProviderPinning struct {
	PublicKeyFile string
	Name          string
}

type SMTPProxy struct {
	Address string
	Network string
}

type Config struct {
	Account         []Account
	ProviderPinning []ProviderPinning
	SMTPProxy       SMTPProxy
}

func FromFile(fileName string) (*Config, error) {
	config := Config{}
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	err = toml.Unmarshal([]byte(fileData), &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
