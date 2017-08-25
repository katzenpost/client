// send.go - mix network client send
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

package proxy

import (
	"github.com/katzenpost/client/crypto/block"
	"github.com/katzenpost/client/path_selection"
	"github.com/katzenpost/client/scheduler"
	"github.com/katzenpost/client/session_pool"
	"github.com/katzenpost/client/storage/egress"
	"github.com/katzenpost/client/user_pki"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/wire/commands"
)

type Sender struct {
	identity     string
	pool         *session_pool.SessionPool
	store        *egress.Store
	routeFactory *path_selection.RouteFactory
	userPKI      user_pki.UserPKI
	handler      *block.Handler
}

func (s *Sender) composeSphinxPacket(blockID *[egress.BlockIDLength]byte, storageBlock *egress.StorageBlock, payload []byte) (*commands.SendPacket, error) {
	forwardPath, replyPath, surbID, err := s.routeFactory.Build(storageBlock.SenderProvider, storageBlock.RecipientProvider, storageBlock.RecipientID)
	if err != nil {
		return nil, err
	}
	surb, surbKeys, err := sphinx.NewSURB(rand.Reader, replyPath)
	if err != nil {
		return nil, err
	}
	storageBlock.SurbKeys = surbKeys
	storageBlock.SendAttempts += 1
	storageBlock.SURBID = surbID
	err = s.store.Update(blockID, storageBlock)
	sphinxPacket, err := sphinx.NewPacket(rand.Reader, forwardPath, append(surb, payload...))
	if err != nil {
		return nil, err
	}
	cmd := commands.SendPacket{
		SphinxPacket: sphinxPacket,
	}
	return &cmd, nil
}

func (s *Sender) Send(blockID *[egress.BlockIDLength]byte, storageBlock *egress.StorageBlock) error {
	receiverKey, err := s.userPKI.GetKey(storageBlock.Recipient)
	if err != nil {
		return err
	}
	blockCiphertext := s.handler.Encrypt(receiverKey, storageBlock.Block)
	cmd, err := s.composeSphinxPacket(blockID, storageBlock, blockCiphertext)
	session, mutex, err := s.pool.Get(s.identity)
	if err != nil {
		return err
	}
	mutex.Lock()
	defer mutex.Unlock()
	err = session.SendCommand(cmd)
	return err
}

type SendScheduler struct {
	sched    *scheduler.PriorityScheduler
	senders  map[string]*Sender
	blockIDs []*[egress.BlockIDLength]byte
	store    *egress.Store
}

func NewSendScheduler(senders map[string]*Sender) *SendScheduler {
	s := SendScheduler{
		senders: senders,
	}
	s.sched = scheduler.New(s.handleSend)
	return &s
}

func (s *SendScheduler) Start() {}

func (s *SendScheduler) Add(blockID *[egress.BlockIDLength]byte) {
	s.blockIDs = append(s.blockIDs, blockID)
}

func (s *SendScheduler) handleSend(task interface{}) {
	storageBlock, ok := task.(*egress.StorageBlock)
	if !ok {
		log.Error("SendScheduler got invalid task from priority scheduler.")
		return
	}
	senders[storageBlock].Send()
}
