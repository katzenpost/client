// smtpd.go - mix network smtp submission proxy
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

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/mail"

	"github.com/siebenmann/smtpd"
)

func smtpServerHandler(conn net.Conn) error {
	cfg := smtpd.Config{} // XXX
	smtpConn := smtpd.NewConn(conn, cfg, nil)
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
