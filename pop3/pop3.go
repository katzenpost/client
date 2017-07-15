// pop3.go - POP3 server.
// Copyright (C) 2017  Yawning Angel.
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

// Package pop3 implements a minimal POP3 server, mostly intended to be ran
// over the loopback interface.
package pop3

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/katzenpost/core/utils"
)

const (
	// Commands
	cmdUser = "USER" // USER name
	cmdPass = "PASS" // PASS string
	// cmdApop = "APOP" // (Optional) APOP name digest
	cmdQuit = "QUIT"
	cmdCapa = "CAPA"

	cmdStat = "STAT"
	cmdList = "LIST" // LIST [msg]
	cmdRetr = "RETR" // RETR [msg]
	cmdDele = "DELE" // DELE [msg]
	cmdNoop = "NOOP"
	cmdRset = "RSET"
	// cmdTop  = "TOP"  // (Optional) TOP msg n
	cmdUIDL = "UIDL" // (Optional) UIDL [msg]

	// RFC 2449 capabilities.
	// capTop  = "TOP"
	capUser = "USER"
	// capSASL = "SASL
	capRespCodes = "RESP-CODES"
	// capLoginDelay     = "LOGIN-DELAY"
	// capPipelining     = "PIPELINING"
	// capExpire         = "EXPIRE"
	capUIDL           = "UIDL"
	capImplementation = "IMPLEMENTATION Katzenpost"

	stateAuthorization sessionState = iota
	stateTransaction
	stateUpdate

	// This is larger than it needs to be (88 bytes is sufficient for all
	// supported commands), but it doesn't hurt.
	maxCmdLength = 128
)

var (
	capabilities = []string{
		capUser,
		capRespCodes,
		capUIDL,
		capImplementation,
		".", // Terminal indicator.
	}

	// ErrInUse is the error returned by a Backend if a user's maildrop is
	// already in use by another session.
	ErrInUse = errors.New("[IN-USE] Do you have another POP session running?")
)

type sessionState int

// Backend is the common interface exposed by a storage backend.
type Backend interface {
	// NewSession authenticates the user specified by the given username and
	// password, and iff the the credentials are valid, locks the user's
	// maildrop and returns a BackendSession instance.
	NewSession(user, pass []byte) (BackendSession, error)
}

// BackendSession is a view into a given user's (locked) maildrop.
type BackendSession interface {
	// Messages returns all of the messages in a user's maildrop.
	Messages() ([][]byte, error)

	// DeleteMessages deletes all of the specified messages, addressed by
	// index into the slice returned by Messages().
	DeleteMessages([]int) error

	// Close unlocks the user's maildrop and tears down the BackendSession.
	Close()
}

// Server is a POP3 server instance.
type Server struct {
	ln net.Listener
	b  Backend
}

// Start starts accepting connections.
func (s *Server) Start() {
	defer s.ln.Close()
	go func() {
		for {
			conn, err := s.ln.Accept()
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Temporary() {
					continue
				}
				return
			}
			ses := newSession(s, conn)
			go ses.handleConn()
		}
	}()
}

// Stop stops accepting connections and tears down the server listener.
// Existing sessions are left as is.
func (s *Server) Stop() {
	s.ln.Close()
}

type session struct {
	srv   *Server
	conn  net.Conn
	bs    BackendSession
	state sessionState

	limRd *io.LimitedReader
	rd    *textproto.Reader
	wr    *textproto.Writer

	messages        [][]byte
	deletedMessages map[int]bool
	cachedUIDLs     []string
}

func (s *session) handleConn() {
	defer s.conn.Close()
	var err error

	// AUTHORIZATION state.
	if err = s.doAuthorization(); err != nil {
		return
	}
	defer s.bs.Close() // maildrop is locked.

	// Retreive the messages from the backend, and cache the UIDLs.
	if s.messages, err = s.bs.Messages(); err != nil {
		return
	}
	s.cacheUIDLs()

	// TRANSACTION state.
	s.doTransaction()
}

func (s *session) doAuthorization() error {
	if s.state != stateAuthorization {
		panic(fmt.Sprintf("pop3: BUG: doAuthorization in state: %d", s.state))
	}

	// Issue a one line greeting
	if err := s.writeOk("POP3 server ready"); err != nil {
		return err
	}

	var user []byte
	prevCmd := ""
authLoop:
	for {
		l, err := s.readLineBytes()
		if err != nil {
			return err
		}

		// Split by whitespace into command and args.
		splitL := bytes.Split(l, []byte{' '})
		cmd := strings.ToUpper(string(splitL[0]))
		switch cmd {
		case cmdUser:
			if len(splitL) != 2 {
				// No user specified.
				if err := s.writeErr("no user specified"); err != nil {
					return err
				}
				break
			}

			// RFC 1939 says that this can only follow the greeting or an
			// unsuccessful user, but there's no harm in being more liberal.
			user = splitL[1]

			// RFC 1939: The server may return a positive response even though
			// no such mailbox exists.
			if err := s.writeOk("%s is a real hoopy frood", string(user)); err != nil {
				return err
			}
		case cmdPass:
			authUser := user
			user = nil // Regardless, a new USER command must be issued.
			if len(splitL) != 2 {
				// No password specified.
				if err := s.writeErr("no password specified"); err != nil {
					return err
				}
				break
			}
			if prevCmd != cmdUser || authUser == nil {
				// PASS can only follow a successful USER.
				if err := s.writeErr("no user specified"); err != nil {
					return err
				}
				break
			}

			// Call the backend to attempt to authenticate, and lock the mail
			// drop.
			var err error
			if s.bs, err = s.srv.b.NewSession(authUser, splitL[1]); err != nil {
				if err == ErrInUse {
					// RFC 2499: IN-USE response code.
					if err = s.writeErr("%s", err.Error()); err != nil {
						return err
					}
				} else if err = s.writeErr("invalid username or password"); err != nil {
					return err
				}
				break
			}

			utils.ExplicitBzero(splitL[1])
			if err = s.writeOk("maildrop locked and ready"); err != nil {
				s.bs.Close()
				return err
			}
			break authLoop // Authenticated.
		case cmdQuit:
			return s.onCmdQuit()
		case cmdCapa:
			if len(splitL) != 1 {
				if err := s.writeArgErr(cmd); err != nil {
					return err
				}
			}
			if err := s.onCmdCapa(); err != nil {
				return err
			}
		default:
			if err := s.writeErr("invalid command: '%s'", cmd); err != nil {
				return err
			}
		}
		prevCmd = cmd
	}

	s.state = stateTransaction
	return nil
}

func (s *session) doTransaction() {
	if s.state != stateTransaction {
		panic(fmt.Sprintf("pop3: BUG: doTransaction in state: %d", s.state))
	}

	for {
		l, err := s.readLine()
		if err != nil {
			return
		}

		// Split by whitespace into command and args.
		splitL := strings.Split(l, " ")
		cmd := strings.ToUpper(splitL[0])
		switch cmd {
		case cmdQuit:
			s.onCmdQuit()
			return
		case cmdCapa:
			if len(splitL) != 1 {
				if err := s.writeArgErr(cmd); err != nil {
					return
				}
			}
			if err := s.onCmdCapa(); err != nil {
				return
			}
		case cmdStat:
			if err := s.onCmdStat(splitL); err != nil {
				return
			}
		case cmdList:
			if err := s.onCmdList(splitL); err != nil {
				return
			}
		case cmdRetr:
			if err := s.onCmdRetr(splitL); err != nil {
				return
			}
		case cmdDele:
			if err := s.onCmdDele(splitL); err != nil {
				return
			}
		case cmdNoop:
			if err := s.onCmdNoop(splitL); err != nil {
				return
			}
		case cmdRset:
			if err := s.onCmdRset(splitL); err != nil {
				return
			}
		case cmdUIDL:
			if err := s.onCmdUIDL(splitL); err != nil {
				return
			}
		default:
			if err := s.writeErr("invalid command: '%s'", cmd); err != nil {
				return
			}
		}
	}
}

func (s *session) onCmdCapa() error {
	if err := s.writeOk("Capability list follows"); err != nil {
		return err
	}
	for _, v := range capabilities {
		if err := s.writeLine("%s", v); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) onCmdQuit() error {
	if s.state == stateTransaction {
		s.state = stateUpdate

		// Update the maildrop (apply DELEed messages).
		toDelete := make([]int, 0, len(s.messages))
		for i := range s.messages {
			if s.deletedMessages[i] {
				toDelete = append(toDelete, i)
			}
		}
		s.bs.DeleteMessages(toDelete) // TODO: Handle errors.
	}
	s.writeOk("POP3 server signing off")
	return io.EOF
}

func (s *session) onCmdStat(splitL []string) error {
	if len(splitL) != 1 {
		return s.writeArgErr(splitL[0])
	}

	n, sz := 0, 0
	for i, v := range s.messages {
		if s.deletedMessages[i] {
			continue
		}
		n, sz = n+1, sz+len(v)
	}

	return s.writeOk("%d %d", n, sz)
}

func (s *session) onCmdList(splitL []string) error {
	switch len(splitL) {
	case 1:
		// Scan listings for all messages.
		if err := s.writeOk("scan listing follows"); err != nil {
			return err
		}
		for i, v := range s.messages {
			if s.deletedMessages[i] {
				continue
			}
			if err := s.writeLine("%d %d", (i + 1), len(v)); err != nil {
				return err
			}
		}
		return s.writeLine(".")
	case 2:
		// Scan listing for one message.
		idx, err := strconv.Atoi(splitL[1])
		if err != nil {
			return s.writeArgErr(splitL[0])
		}
		if idx < 1 || idx > len(s.messages) || s.deletedMessages[idx-1] {
			return s.writeErr("no such message")
		}
		return s.writeOk("%d %d", idx, len(s.messages[idx-1]))
	default:
		return s.writeArgErr(splitL[0])
	}
}

func (s *session) onCmdRetr(splitL []string) error {
	if len(splitL) != 2 {
		return s.writeArgErr(splitL[0])
	}
	idx, err := strconv.Atoi(splitL[1])
	if err != nil {
		return s.writeArgErr(splitL[0])
	}
	if idx < 1 || idx > len(s.messages) || s.deletedMessages[idx-1] {
		return s.writeErr("no such message")
	}

	if err := s.writeOk("message follows"); err != nil {
		return err
	}
	// XXX: Will lines ever be > bufio.MaxScanTokenSize (64 KiB)?
	scanner := bufio.NewScanner(bytes.NewReader(s.messages[idx-1]))
	for scanner.Scan() {
		line := scanner.Text()
		if line[0] == '.' { // See RFC 1939 Section 3 ("byte-stuffed")
			line = "." + line
		}
		if err := s.writeLine("%s", line); err != nil {
			return err
		}
	}
	// XXX: Check scanner.Err(), though I'm not sure there's a good way to
	// recover from it.
	return s.writeLine(".")
}

func (s *session) onCmdDele(splitL []string) error {
	if len(splitL) != 2 {
		return s.writeArgErr(splitL[0])
	}
	idx, err := strconv.Atoi(splitL[1])
	if err != nil {
		return s.writeArgErr(splitL[0])
	}
	if idx < 1 || idx > len(s.messages) {
		return s.writeErr("no such message")
	}
	if s.deletedMessages[idx-1] {
		return s.writeErr("message %d already deleted", idx)
	}

	s.deletedMessages[idx-1] = true

	return s.writeOk("message %d deleted", idx)
}

func (s *session) onCmdNoop(splitL []string) error {
	if len(splitL) != 1 {
		return s.writeArgErr(splitL[0])
	}

	return s.writeOk("")
}

func (s *session) onCmdRset(splitL []string) error {
	if len(splitL) != 1 {
		return s.writeArgErr(splitL[0])
	}

	s.deletedMessages = make(map[int]bool)
	return s.writeOk("")
}

func (s *session) onCmdUIDL(splitL []string) error {
	switch len(splitL) {
	case 1:
		// UIDL for all messages.
		if err := s.writeOk("unique-id listing follows"); err != nil {
			return err
		}
		for i := range s.messages {
			if s.deletedMessages[i] {
				continue
			}

			if err := s.writeLine("%d %s", (i + 1), s.cachedUIDLs[i]); err != nil {
				return err
			}
		}
		return s.writeLine(".")
	case 2:
		// UIDL for one message.
		idx, err := strconv.Atoi(splitL[1])
		if err != nil {
			return s.writeArgErr(splitL[0])
		}
		if idx < 1 || idx > len(s.messages) || s.deletedMessages[idx-1] {
			return s.writeErr("no such message")
		}
		return s.writeOk("%d %s", idx, s.cachedUIDLs[idx-1])
	default:
		return s.writeArgErr(splitL[0])
	}
}

func (s *session) writeLine(f string, a ...interface{}) error {
	return s.wr.PrintfLine(f, a...)
}

func (s *session) writeOk(f string, a ...interface{}) error {
	// Technically this should send `+OK\r\n` if there's no additional status
	// information, however RFC 1957 discusses ancient (1990s) clients that
	// expect a space.
	resp := fmt.Sprintf(f, a...)
	return s.wr.PrintfLine("+OK %s", resp)
}

func (s *session) writeErr(f string, a ...interface{}) error {
	resp := fmt.Sprintf(f, a...)
	return s.wr.PrintfLine("-ERR %s", resp)
}

func (s *session) writeArgErr(cmd string) error {
	return s.writeErr("invalid arguments to '%s'", cmd)
}

func (s *session) readLineBytes() ([]byte, error) {
	l, err := s.rd.ReadLineBytes()
	if err != nil {
		return nil, err
	}
	s.limRd.N = maxCmdLength
	return l, nil
}

func (s *session) readLine() (string, error) {
	l, err := s.rd.ReadLine()
	if err != nil {
		return "", err
	}
	s.limRd.N = maxCmdLength
	return l, nil
}

func (s *session) cacheUIDLs() {
	for _, v := range s.messages {
		// Use SHA256-128 as the UIDL hash.
		sum := sha256.Sum256(v)
		s.cachedUIDLs = append(s.cachedUIDLs, hex.EncodeToString(sum[:16]))
	}
}

func newSession(srv *Server, conn net.Conn) *session {
	s := new(session)
	s.srv = srv
	s.conn = conn
	s.limRd = &io.LimitedReader{R: conn, N: maxCmdLength}
	s.rd = textproto.NewReader(bufio.NewReader(s.limRd))
	s.wr = textproto.NewWriter(bufio.NewWriter(s.conn))
	s.deletedMessages = make(map[int]bool)
	return s
}
