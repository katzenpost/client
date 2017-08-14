// smtp_proxy.go - mix network client smtp submission proxy
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

// Package proxy provides mixnet client proxies
package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"strings"

	"github.com/katzenpost/client/block"
	"github.com/katzenpost/client/config"
	clientconstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/path_selection"
	"github.com/katzenpost/client/session_pool"
	"github.com/katzenpost/client/user_pki"
	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/sphinx"
	sphinxconstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/wire/commands"
	"github.com/op/go-logging"
	"github.com/siebenmann/smtpd"
)

var log = logging.MustGetLogger("mixclient")

// logWriter is used to present the io.Reader interface
// to our SMTP library for logging. this is only required
// because of our SMTP library choice and isn't otherwise needed.
type logWriter struct {
	log *logging.Logger
}

// newLogWriter creates a new logWriter
func newLogWriter(log *logging.Logger) *logWriter {
	writer := logWriter{
		log: log,
	}
	return &writer
}

// Write writes a message to the log
func (w *logWriter) Write(p []byte) (int, error) {
	w.log.Debug(string(p))
	return len(p), nil
}

// isStringInList returns true if key is found in list
func isStringInList(key string, list []string) bool {
	k := strings.ToLower(key)
	ret := false
	for i := 0; i < len(list); i++ {
		if k == strings.ToLower(list[i]) {
			return true
		}
	}
	return ret
}

// getWhiteListedFields returns a new header composed of only
// the entries in the given header which our found in the whitelist
func getWhiteListedFields(header *mail.Header, whitelist []string) *mail.Header {
	rHeader := make(mail.Header)
	for k, v := range *header {
		if isStringInList(k, whitelist) {
			rHeader[k] = v
		}
	}
	return &rHeader
}

// getMessageIdentities returns the sender and receiver identity strings
// or an error
func getMessageIdentities(message *mail.Message) (string, string, error) {
	sender, err := mail.ParseAddress(message.Header.Get("From"))
	if err != nil {
		return "", "", err
	}
	receiver, err := mail.ParseAddress(message.Header.Get("To"))
	if err != nil {
		return "", "", err
	}
	return sender.Address, receiver.Address, nil
}

// parseMessage returns a parsed message structure given a string
func parseMessage(message string) (*mail.Message, error) {
	messageBuffer := bytes.NewBuffer([]byte(message))
	m, err := mail.ReadMessage(messageBuffer)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// stringFromHeader serializes the header structure into a string
func stringFromHeader(header mail.Header) (string, error) {
	messageBuffer := new(bytes.Buffer)
	for key, _ := range header {
		value := header.Get(key)
		_, err := messageBuffer.WriteString(fmt.Sprintf("%s: ", key))
		if err != nil {
			return "", err
		}
		_, err = messageBuffer.WriteString(fmt.Sprintf("%s\n", value))
		if err != nil {
			return "", err
		}
	}
	return messageBuffer.String(), nil
}

// stringFromHeaderBody serializes the given header and body
func stringFromHeaderBody(header mail.Header, body io.Reader) (string, error) {
	buf := new(bytes.Buffer)
	headerStr, err := stringFromHeader(header)
	if err != nil {
		return "", err
	}
	_, err = buf.WriteString(headerStr)
	if err != nil {
		return "", err
	}
	_, err = buf.ReadFrom(body)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// SubmitProxy handles SMTP mail submissions. This means we act as an SMTP
// daemon, accepting e-mail messages and proxying them to the mix network
// via the Providers. Furthermore I instantiate an instance of the
// Poisson Stop and Wait ARQ reliability protocol scheme as well as three layers of
// crypto:
//
//    * link layer / sphinx layer / end to end layer
//
// Note: the end to end crypto is Client to Client while the Provider
// participates in our reliability protocol receiving ciphertext on behalf
// of the recipient.
//
// The outgoing messages are persisted to disk in a cryptographically sealed file vault.
// If the client stops operating before receiving the corresponding ACK message,
// the client will later be able to retreive messages from disk and retransmit them.
type SubmitProxy struct {
	accounts *config.Accounts

	// randomReader is an implementation of the io.Reader interface
	// which is used to generate ephemeral keys for our wire protocol's
	// cryptographic handshake messages
	randomReader io.Reader

	// userPKI implements the UserPKI interface
	userPKI user_pki.UserPKI

	// session pool of connections to each provider
	sessionPool *session_pool.SessionPool

	routeFactory *path_selection.RouteFactory

	whitelist []string
}

// NewSubmitProxy creates a new SubmitProxy struct
func NewSubmitProxy(routeFactory *path_selection.RouteFactory, accounts *config.Accounts, randomReader io.Reader, userPki user_pki.UserPKI, pool *session_pool.SessionPool) *SubmitProxy {
	submissionProxy := SubmitProxy{
		routeFactory: routeFactory,
		accounts:     accounts,
		randomReader: randomReader,
		userPKI:      userPki,
		sessionPool:  pool,
		whitelist: []string{ // XXX yawning fix me
			"To",
			"From",
			"Subject",
			"MIME-Version",
			"Content-Type",
		},
	}
	return &submissionProxy
}

// fragmentMessage fragments a message into a slice of blocks
func (p *SubmitProxy) fragmentMessage(message []byte) ([]*block.Block, error) {
	blocks := []*block.Block{}
	if len(message) <= constants.ForwardPayloadLength {
		id := [clientconstants.MessageIDLength]byte{}
		_, err := rand.Reader.Read(id[:])
		if err != nil {
			return nil, err
		}
		block := block.Block{
			MessageID:   id,
			TotalBlocks: 1,
			BlockID:     0,
			Block:       message,
		}
		blocks = append(blocks, &block)
	} else {
		return nil, errors.New("error: fragmentation not yet implemented")
	}
	return blocks, nil
}

// sendMessage sends a message to a given receiver identity
//
// The sender e-mail address is used to select the client's end to end cryptographic
// identity in sending end to end messages, ACK messaging queuing identification on the provider
// and link layer authentication with the associated Provider mixnet service.
//
// TODO: implement the Stop and Wait ARQ protocol scheme here!
func (p *SubmitProxy) sendMessage(sender, receiver string, message []byte) error {
	log.Debugf("sendMessage no-op function: sender %s receiver %s", sender, receiver)
	log.Debugf("message:\n%s\n", string(message))

	blocks, err := p.fragmentMessage(message)
	if err != nil {
		return err
	}
	senderKey, err := p.accounts.GetIdentityKey(sender)
	if err != nil {
		return err
	}
	receiverKey, err := p.userPKI.GetKey(receiver)
	if err != nil {
		return err
	}
	handler := block.NewHandler(senderKey, rand.Reader)
	for _, block := range blocks {
		blockCiphertext := handler.Encrypt(receiverKey, block)
		_, senderProvider, err := config.SplitEmail(sender)
		if err != nil {
			return err
		}
		recipientUser, recipientProvider, err := config.SplitEmail(receiver)
		if err != nil {
			return err
		}
		recipientID := [sphinxconstants.RecipientIDLength]byte{}
		copy(recipientID[:], recipientUser)
		// XXX todo: use the replyPath to compose the SURB-ACK
		forwardPath, _, _, err := p.routeFactory.Build(senderProvider, recipientProvider, &recipientID)
		if err != nil {
			return err
		}
		sphinxPacket, err := sphinx.NewPacket(rand.Reader, forwardPath, blockCiphertext)
		if err != nil {
			return err
		}
		cmd := commands.SendPacket{
			SphinxPacket: sphinxPacket,
		}
		session, err := p.sessionPool.Get(sender)
		if err != nil {
			return err
		}
		err = session.SendCommand(cmd)
		if err != nil {
			return err
		}
	}
	return nil
}

// handleSMTPSubmission handles the SMTP submissions
// and proxies them to the mix network.
func (p *SubmitProxy) HandleSMTPSubmission(conn net.Conn) error {
	cfg := smtpd.Config{} // XXX
	logWriter := newLogWriter(log)
	smtpConn := smtpd.NewConn(conn, cfg, logWriter)
	sender := ""
	receiver := ""
	for {
		event := smtpConn.Next()
		if event.What == smtpd.DONE || event.What == smtpd.ABORT {
			return nil
		}
		if event.What == smtpd.COMMAND && event.Cmd == smtpd.MAILFROM {
			senderAddr, err := mail.ParseAddress(event.Arg)
			if err != nil {
				log.Debug("sender address parse fail")
				smtpConn.Reject()
				return err
			}
			sender = senderAddr.Address
			if !p.accounts.HasIdentity(sender) {
				log.Debug("client identity not found")
				smtpConn.Reject()
				return nil
			}
		}
		if event.What == smtpd.COMMAND && event.Cmd == smtpd.RCPTTO {
			receiverAddr, err := mail.ParseAddress(strings.ToLower(event.Arg))
			if err != nil {
				log.Debug("recipient address parse fail")
				smtpConn.Reject()
				return err
			}
			receiver = receiverAddr.Address
			_, err = p.userPKI.GetKey(receiver)
			if err != nil {
				log.Debugf("user PKI: email %s not found", receiver)
				smtpConn.Reject()
				return nil
			}
		}
		if event.What == smtpd.GOTDATA {
			message, err := parseMessage(event.Arg)
			if err != nil {
				return err
			}
			id := message.Header.Get("X-Panoramix-Sender-Identity-Key")
			if len(id) != 0 {
				log.Debug("Bad message received. Found X-Panoramix-Sender-Identity-Key in header.")
				smtpConn.Reject()
				return nil
			}
			header := getWhiteListedFields(&message.Header, p.whitelist)
			messageString, err := stringFromHeaderBody(*header, message.Body)
			if err != nil {
				return err
			}
			err = p.sendMessage(sender, receiver, []byte(messageString))
			if err != nil {
				return err
			}
			return nil
		}
	}
	return nil
}
