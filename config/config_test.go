// config_test.go - mixnet client configuration tests
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
DataDir = "blah"

[PKI]
[PKI.Nonvoting]
Address = "127.0.0.1:6999"
PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

[Logging]
Level = "DEBUG"

[[UserPKI]]
  Email = "alice@acme.com"
  PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

[[UserPKI]]
  Email = "bob@nsa.gov"
  PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

[[Account]]
  Name = "alice"
  Provider = "acme.com"
  PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

[[Account]]
  Name = "Carol"
  Provider = "ProviderOfNet"
  PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

[[Account]]
  Name = "Eve"
  Provider = "Trustworthy"
  PublicKey = "kAiVchOBwHVtKJVFJLsdCQ9UyN2SlfhLHYqT8ePBetg="

[POP3Proxy]
  Address = "127.0.0.1:9006"
  Network = "tcp"

[SMTPProxy]
  Address = "127.0.0.1:2525"
  Network = "tcp"
`
	tmpConfigFile, err := ioutil.TempFile("/tmp", "configTomlTest")
	require.NoError(err, "TempFile failed")
	_, err = tmpConfigFile.Write([]byte(tomlConfigStr))
	require.NoError(err, "Write failed")
	config, err := LoadFile(tmpConfigFile.Name())
	require.NoError(err, "FromFile failed")
	t.Logf("DataDir %s", config.DataDir)
	t.Logf("PKI address %s", config.PKI.Nonvoting.Address)
	t.Logf("1st account name %s", config.Account[0].Name)
	t.Logf("POP3Proxy address %s", config.POP3Proxy.Address)
}
