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

// Package provides mixnet client configuration utilities
package config

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	require := require.New(t)

	tomlConfigStr := `
[[Account]]
  Name = "Alice"
  Provider = "Acme"

[[Account]]
  Name = "Carol"
  Provider = "ProviderOfNet"

[[Account]]
  Name = "Eve"
  Provider = "Trustworthy"

[[ProviderPinning]]
  PublicKeyFile = "/blah/blah/certs/acme.pem"
  Name = "Acme"

[SMTPProxy]
  Address = "127.0.0.1:2525"
  Network = "tcp"
`
	tmpConfigFile, err := ioutil.TempFile("/tmp", "configTomlTest")
	require.NoError(err, "TempFile failed")
	_, err = tmpConfigFile.Write([]byte(tomlConfigStr))
	require.NoError(err, "Write failed")
	config, err := FromFile(tmpConfigFile.Name())
	require.NoError(err, "FromFile failed")
	t.Log(config)
}
