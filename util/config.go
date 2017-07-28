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

// TomlConfig is used for unmarshaling our client toml configuration
type TomlConfig struct {
	Accounts         []Account
	ProviderPinnings []ProviderPining
}

type Account struct {
	Name     string
	Provider string
}

type ProviderPining struct {
	Name            string
	CertificateFile string
}

// LoadConfig returns a *Config given a filepath to a configuration file
func LoadConfig(configFilePath string) (*TomlConfig, error) {
	config := TomlConfig{}
	lines, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}
	if err := toml.Unmarshal([]byte(lines), &config); err != nil {
		return nil, err
	}
	return &config, nil
}
