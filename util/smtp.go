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
	"io/ioutil"
	"net"
	"net/mail"

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

// MailSubmissionProxy handles SMTP mail submissions
// and wraps them in many layers of crypto and then sends
// them to the "Provider"
type MailSubmissionProxy struct {
}

func (p *MailSubmissionProxy) handleSMTPSubmission(conn net.Conn) error {
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
			fmt.Println("MAIL DATA")
			message, err := mail.ReadMessage(messageBuffer)
			if err != nil {
				return err
			}
			header := message.Header
			fmt.Println("Date:", header.Get("Date"))
			fmt.Println("From:", header.Get("From"))
			fmt.Println("To:", header.Get("To"))
			fmt.Println("Subject:", header.Get("Subject"))
			body, err := ioutil.ReadAll(message.Body)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s", body)
			return nil
		}
	}
	return nil
}
