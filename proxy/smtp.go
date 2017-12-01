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
	"fmt"
	"io"
	"net"
	"net/mail"
	"strings"

	"github.com/katzenpost/client/config"
	"github.com/katzenpost/client/path_selection"
	"github.com/katzenpost/client/storage"
	"github.com/katzenpost/client/user_pki"
	"github.com/katzenpost/core/log"
	sphinxconstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/op/go-logging"
	"github.com/siebenmann/smtpd"
)

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

// SMTPProxy handles SMTP mail submissions. This means we act as an SMTP
// daemon, accepting e-mail messages and proxying them to the mix network
// via the Providers.
type SMTPProxy struct {
	log        *logging.Logger
	logBackend *log.Backend

	// accounts is a mapping of emails to private keys
	accounts *config.AccountsMap

	// randomReader is an implementation of the io.Reader interface
	// which is used to generate ephemeral keys for our wire protocol's
	// cryptographic handshake messages
	randomReader io.Reader

	// userPKI implements the UserPKI interface
	userPKI user_pki.UserPKI

	// store is used to persist messages to disk
	store *storage.Store

	// routeFactory is used to create mixnet routes
	routeFactory *path_selection.RouteFactory

	whitelist []string

	// scheduler send message blocks and implements the Stop and Wait ARQ
	scheduler *SendScheduler
}

// NewSmtpProxy creates a new SMTPProxy struct
func NewSmtpProxy(logBackend *log.Backend, accounts *config.AccountsMap, randomReader io.Reader, userPki user_pki.UserPKI, store *storage.Store, routeFactory *path_selection.RouteFactory, scheduler *SendScheduler) *SMTPProxy {
	submissionProxy := SMTPProxy{
		log:          logBackend.GetLogger("SMTPProxy"),
		logBackend:   logBackend,
		accounts:     accounts,
		randomReader: randomReader,
		userPKI:      userPki,
		store:        store,
		routeFactory: routeFactory,
		scheduler:    scheduler,
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

// enqueueMessage enqueues the message in our persistent message store
// so that it can soon be sent on it's way to the recipient.
func (p *SMTPProxy) enqueueMessage(sender, receiver string, message []byte) error {
	blocks, err := fragmentMessage(p.randomReader, message)
	if err != nil {
		return err
	}
	for _, b := range blocks {
		senderUser, senderProvider, err := config.SplitEmail(sender)
		if err != nil {
			return err
		}
		recipientUser, recipientProvider, err := config.SplitEmail(receiver)
		if err != nil {
			return err
		}
		recipientID := [sphinxconstants.RecipientIDLength]byte{}
		copy(recipientID[:], recipientUser)
		senderID := [sphinxconstants.RecipientIDLength]byte{}
		copy(senderID[:], senderUser)
		storageBlock := storage.EgressBlock{
			Sender:            sender,
			SenderProvider:    senderProvider,
			Recipient:         receiver,
			RecipientID:       recipientID,
			SenderID:          senderID,
			RecipientProvider: recipientProvider,
			SendAttempts:      uint8(0),
			Block:             *b,
		}
		blockID, err := p.store.PutEgressBlock(&storageBlock)
		if err != nil {
			return err
		}
		p.scheduler.Send(sender, blockID, &storageBlock)
	}
	return nil
}

// handleSMTPSubmission handles the SMTP submissions
func (p *SMTPProxy) HandleSMTPSubmission(conn net.Conn) error {
	cfg := smtpd.Config{} // XXX
	logWriter := p.logBackend.GetLogWriter("SMTPProxy-SMTP", "DEBUG")
	smtpConn := smtpd.NewConn(conn, cfg, logWriter)
	sender := ""
	receiver := ""
	for {
		event := smtpConn.Next()
		if event.What == smtpd.DONE || event.What == smtpd.ABORT {
			p.log.Debug("SMTP session done.")
			return nil
		}
		if event.What == smtpd.COMMAND && event.Cmd == smtpd.MAILFROM {
			p.log.Debug("Mail from command")
			senderAddr, err := mail.ParseAddress(event.Arg)
			if err != nil {
				p.log.Error("sender address parse fail")
				smtpConn.Reject()
				return err
			}
			sender = senderAddr.Address
			if _, err = p.accounts.GetIdentityKey(sender); err != nil {
				p.log.Error("client identity not found")
				smtpConn.Reject()
				return nil
			}
		}
		if event.What == smtpd.COMMAND && event.Cmd == smtpd.RCPTTO {
			p.log.Debug("Rcpt to command")
			receiverAddr, err := mail.ParseAddress(strings.ToLower(event.Arg))
			if err != nil {
				p.log.Error("recipient address parse fail")
				smtpConn.Reject()
				return err
			}
			receiver = receiverAddr.Address
			_, err = p.userPKI.GetKey(receiver)
			if err != nil {
				p.log.Errorf("user PKI: email %s not found", receiver)
				smtpConn.Reject()
				return nil
			}
		}
		if event.What == smtpd.GOTDATA {
			p.log.Debug("Data command")
			message, err := parseMessage(event.Arg)
			if err != nil {
				return err
			}
			id := message.Header.Get("X-Panoramix-Sender-Identity-Key")
			if len(id) != 0 {
				p.log.Error("Bad message received. Found X-Panoramix-Sender-Identity-Key in header.")
				smtpConn.Reject()
				return nil
			}
			header := getWhiteListedFields(&message.Header, p.whitelist)
			messageString, err := stringFromHeaderBody(*header, message.Body)
			if err != nil {
				p.log.Errorf("stringFromHeaderBody failure: %s", err)
				return err
			}
			err = p.enqueueMessage(sender, receiver, []byte(messageString))
			if err != nil {
				p.log.Errorf("enqueueMessage failure: %s", err)
				return err
			}
		}
	}
	return nil
}
