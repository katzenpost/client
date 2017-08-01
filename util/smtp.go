// smtp.go - mix network smtp submission proxy
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
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/mail"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/wire"
	"github.com/op/go-logging"
	"github.com/siebenmann/smtpd"
)

type logWriter struct {
	log *logging.Logger
}

func newLogWriter(log *logging.Logger) *logWriter {
	writer := logWriter{
		log: log,
	}
	return &writer
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.log.Debug(string(p))
	return len(p), nil
}

// SubmitProxy handles SMTP mail submissions
// and wraps them in 3 delicious layers of crypto and then sends
// them to the "Provider":
//
//    * link layer / sphinx layer / end to end layer
//
type SubmitProxy struct {
	Authenticator wire.PeerAuthenticator
	RandomReader  io.Reader
	UserKeyMap    map[string]*ecdh.PrivateKey
}

func NewSubmitProxy(authenticator wire.PeerAuthenticator, randomReader io.Reader, userKeyMap map[string]*ecdh.PrivateKey) *SubmitProxy {
	submissionProxy := SubmitProxy{
		Authenticator: authenticator,
		RandomReader:  randomReader,
		UserKeyMap:    userKeyMap,
	}
	return &submissionProxy
}

func (p *SubmitProxy) newSession(provider string) (*wire.Session, error) {
	sessionConfig := wire.SessionConfig{
		Authenticator:  p.Authenticator,
		AdditionalData: []byte(provider),
		// XXX AuthenticationKey: wireClientKey,
		//EndClientKey: fufu,
	}
	session, err := wire.NewSession(&sessionConfig, true)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (p *SubmitProxy) getSenderReceiverKeys(sender, receiver string) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	sendKey, ok := p.UserKeyMap[sender]
	if !ok {
		return nil, nil, fmt.Errorf("Indentity key lookup failure: cannot find key for %s", sender)
	}
	recipientPubKey, err := p.userPki.GetKey(recipient)
	if err != nil {
		return nil, nil, err
	}
	return sendKey, recipientPubKey, nil
}

func (p *SubmitProxy) getSession(sender string) (*wire.Session, error) {
	session, ok := p.sessionMap[sender]
	if !ok {

	}
	// func NewSession(cfg *SessionConfig, isInitiator bool) (*Session, error)
	session := wire.Session{} // XXX
	return &session
}

// ciphertextBlocksFromMessage transforms the given message into a
// slice of encrypted blocks
func (p *SubmitProxy) encryptedBlocksFromMessage(senderKey *ecdh.PrivateKey, receiverKey *ecdh.PublicKey, message []byte) ([][]byte, error) {
	// XXX todo: feature versions of this function can
	// handle fragmentation and padding. but for now
	// just return an error if not exactly block length.
	// also in the future we will have several specific
	// block sizes.
	if len(message) != block.BlockLength {
		return nil, errors.New("message size != block size")
	}
	blockHandler := block.NewHandler(senderKey, p.randomReader)
	messageId := make([]byte, constants.MessageIDLength)
	p.randomReader.Read(&messageId)
	messageBlock := block.Block{
		MessageID:   messageId,
		TotalBlocks: uint16(1), // XXX
		BlockID:     uint16(0), // XXX
		Block:       []byte(message),
	}
	ciphertext := blockHandler.Encrypt(receiverKey, messageBlock)
	ret := [][]byte{
		ciphertext,
	}
	return ret
}

func (p *SubmitProxy) getWireProtocolKeys() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {

}

func (p *SubmitProxy) composeSphinxPacket(payload []byte) ([]byte, error) {
	var err error
	path, err := p.createNewPath() // XXX doesn't exist yet
	if err != nil {
		return nil, err
	}
	packet, err := sphinx.NewPacket(p.RandomReader, path, payload)
	if err != nil {
		return nil, err
	}
	return packet, nil
}

func (p *SubmitProxy) sendCiphertextBlock(sender, receiver string, blockCiphertext []byte) error {
	senderKey, receiverKey, err := p.getWireProtocolKeys(sender, receiver)
	if err != nil {
		return nil, nil, err
	}
	session := p.getSession(sender)
	sphinxPaclet, err := p.composeSphinxPacket(blockCiphertext)

	sendPacket := commands.SendPacket{
		SphinxPacket: sphinxPacket,
	}
	session.SendCommand(sendCmd)
	return nil
}

func (p *SubmitProxy) sendMessage(sender, receiver string, message []byte) error {
	senderKey, receiverKey, err := p.getSenderReceiverKeys(sender, receiver)
	if err != nil {
		return err
	}

	// XXX for the time being it always returns 1 block
	blocks, err := encryptedBlocksFromMessage(senderKey, receiverKey, message)
	if err != nil {
		return err
	}
	for i := 0; i < len(blocks); i++ {
		err = p.sendCiphertextBlock(sender, receiver, blocks[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *SubmitProxy) handleSMTPSubmission(conn net.Conn) error {
	cfg := smtpd.Config{} // XXX
	logWriter := newLogWriter(log)
	smtpConn := smtpd.NewConn(conn, cfg, logWriter)
	for {
		event := smtpConn.Next()
		if event.What == smtpd.DONE || event.What == smtpd.ABORT {
			return nil
		}
		if event.What == smtpd.GOTDATA {
			messageBuffer := bytes.NewBuffer([]byte(event.Arg))
			message, err := mail.ReadMessage(messageBuffer)
			if err != nil {
				return err
			}
			header := message.Header
			sender := header.Get("From")
			receiver := header.Get("To")
			err = p.sendMessage(sender, receiver, message)
			if err != nil {
				return err
			}
			return nil
		}
	}
	return nil
}
