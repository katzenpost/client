// common.go - mixnet client common types
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

// Package common provides common types for constructing mixnet clients.
package common

// Config is a mix client configuration struct
type Config struct {
	LongtermKeyFilePath string
}

// LoadConfig returns a *Config given a filepath to a configuration file
func LoadConfig(configFilePath string) (*Config, error) {
	config := Config{}
	// XXX todo: fix me
	return &config, nil
}
