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

func CiphertextBlocksFromMessage(message []byte) ([]byte, error) {
	if len(message) != block.BlockLength {

	}

	blockHandler := block.NewHandler(p.UserKeyMap[sender], p.randomReader)
	messageId := make([]byte, constants.MessageIDLength)
	p.randomReader.Read(&messageId)
	messageBlock := block.Block{
		MessageID:   messageId,
		TotalBlocks: uint16(1), // XXX
		BlockID:     uint16(0), // XXX
		Block:       []byte(event.Arg),
	}
	ciphertext := blockHandler.Encrypt(recipientPubKey, messageBlock)

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
			_, ok := p.UserKeyMap[sender]
			if !ok {
				return fmt.Errorf("Indentity key lookup failure: cannot find key for %s", sender)
			}

			recipient := header.Get("To")
			recipientPubKey, err := p.userPki.GetKey(recipient)
			if err != nil {
				return err
			}
			body, err := ioutil.ReadAll(message.Body)
			if err != nil {
				log.Fatal(err)
			}

			// XXX send message; encrypt Block to peerPubKey
			// specified sender identity
			p.sendBlock()
			return nil
		}
	}
	return nil
}
