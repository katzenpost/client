// main.go - Katzenpost ping test
// Copyright (C) 2018, 2019  David Stainton
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

package client

import (
	"fmt"
	"testing"

	"github.com/katzenpost/client/config"
	"github.com/stretchr/testify/assert"
)

func TestServerStartShutdown(t *testing.T) {
	assert := assert.New(t)

	configFile := "testdata/catshadow.toml"
	service := "loop"
	cfg, err := config.LoadFile(configFile)
	assert.NoError(err)
	cfg, linkKey := AutoRegisterRandomClient(cfg)

	// create a client and connect to the mixnet Provider
	c, err := New(cfg)
	assert.NoError(err)
	s, err := c.NewSession(linkKey)
	assert.NoError(err)

	serviceDesc, err := s.GetService(service)
	assert.NoError(err)
	fmt.Printf("sending ping to %s@%s\n", serviceDesc.Name, serviceDesc.Provider)

	mesg, err := s.SendUnreliableMessage(serviceDesc.Name, serviceDesc.Provider, []byte("hello"))
	assert.NoError(err)
	fmt.Printf("reply: %s\n", mesg)
	fmt.Println("Done. Shutting down.")
	c.Shutdown()
}
