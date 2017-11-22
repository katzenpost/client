// client.go - Katzenpost client.
// Copyright (C) 2017  David Stainton, Yawning Angel
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

// Package client provides the Katzenpost client.
package client

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	nClient "github.com/katzenpost/authority/nonvoting/client"
	"github.com/katzenpost/client/config"
	"github.com/katzenpost/client/user_pki"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/op/go-logging"
)

// Client is a Katzenpost client instance.
type Client struct {
	cfg *config.Config

	logBackend *log.Backend
	log        *logging.Logger

	accountsMap *config.AccountsMap

	userPKI user_pki.UserPKI
	mixPKI  pki.Client

	pinnedProviders map[[255]byte]*ecdh.PublicKey
}

func (c *Client) initDataDir() error {
	const dirMode = os.ModeDir | 0700
	d := c.cfg.DataDir

	// Initialize the data directory, by ensuring that it exists (or can be
	// created), and that it has the appropriate permissions.
	if fi, err := os.Lstat(d); err != nil {
		// Directory doesn't exist, create one.
		if !os.IsNotExist(err) {
			return fmt.Errorf("client: failed to stat() DataDir: %v", err)
		}
		if err = os.Mkdir(d, dirMode); err != nil {
			return fmt.Errorf("client: failed to create DataDir: %v", err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("client: DataDir '%v' is not a directory", d)
		}
		if fi.Mode() != dirMode {
			return fmt.Errorf("client: DataDir '%v' has invalid permissions '%v'", d, fi.Mode())
		}
	}

	return nil
}

func (c *Client) initLogging() error {
	p := c.cfg.Logging.File
	if !c.cfg.Logging.Disable && c.cfg.Logging.File != "" {
		if !filepath.IsAbs(p) {
			p = filepath.Join(c.cfg.DataDir, p)
		}
	}
	var err error
	c.logBackend, err = log.New(p, c.cfg.Logging.Level, c.cfg.Logging.Disable)
	if err == nil {
		c.log = c.logBackend.GetLogger("client")
	}
	return err
}

// New returns a new Client instance parameterized with the specified
// configuration.
func New(cfg *config.Config, accountsMap *config.AccountsMap, userPKI user_pki.UserPKI) (*Client, error) {
	var err error
	c := new(Client)
	c.cfg = cfg
	if err = c.initDataDir(); err != nil {
		return nil, err
	}
	if err = c.initLogging(); err != nil {
		return nil, err
	}
	c.log.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")
	if c.cfg.Logging.Level == "DEBUG" {
		c.log.Warning("Debug logging is enabled.")
	}

	if accountsMap == nil {
		return nil, errors.New("accountsMap cannot be nil")
	}
	c.accountsMap = accountsMap
	c.userPKI = userPKI

	authPk := new(eddsa.PublicKey)
	err = authPk.FromString(c.cfg.PKI.Nonvoting.PublicKey)
	if err != nil {
		return nil, err
	}
	pkiCfg := &nClient.Config{
		LogBackend: c.logBackend,
		Address:    c.cfg.PKI.Nonvoting.Address,
		PublicKey:  authPk,
	}
	c.mixPKI, err = nClient.New(pkiCfg)
	if err != nil {
		return nil, err
	}

	c.pinnedProviders, err = cfg.GetProviderPinnedKeys()
	if err != nil {
		return nil, err
	}

	return c, nil
}
