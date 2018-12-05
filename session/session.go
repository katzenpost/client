// session.go - mixnet client session
// Copyright (C) 2018  David Stainton.
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

package session

import (
	"encoding/binary"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand"
	"path/filepath"
	"sync"
	"time"

	"github.com/katzenpost/client/config"
	cConstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/internal/pkiclient"
	"github.com/katzenpost/client/poisson"
	"github.com/katzenpost/client/utils"
	coreConstants "github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/sphinx/constants"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	cutils "github.com/katzenpost/core/utils"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/minclient"
	"github.com/katzenpost/noise"
	"gopkg.in/op/go-logging.v1"
)

const (
	maxMsgLen = 1048576
	macLen    = 16
)

var (
	errMsgSize              = errors.New("client/session: invalid message size")
)

// Session is the struct type that keeps state for a given session.
type Session struct {
	worker.Worker

	cfg       *config.Config
	pkiClient pki.Client
	minclient *minclient.Client
	log       *logging.Logger

	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once

	// XXX Our client scheduler is different than specified in
	// "The Loopix Anonymity System".
	//
	// We use λP a poisson process to control the interval between
	// popping items off our send egress FIFO queue. If the queue is ever
	// empty we send a decoy loop message.
	pTimer *poisson.Fount

	linkKey   *ecdh.PrivateKey
	opCh      chan workerOp
	Messages  map[string]chan []byte
	onlineAt  time.Time
	hasPKIDoc bool

	egressQueue     EgressQueue
	egressQueueLock *sync.Mutex

	surbIDMap      map[[sConstants.SURBIDLength]byte]*MessageRef
	messageIDMap   map[[cConstants.MessageIDLength]byte]*MessageRef
	replyNotifyMap map[[cConstants.MessageIDLength]byte]chan []byte
	mapLock        *sync.Mutex

	// cipherstates for e2e channels
	rxs map[string]*noise.CipherState
	txs map[string]*noise.CipherState
}

// KatzenPeer implements Addr
type KatzenPeer struct {
	User string
	Provider string
}

func (k *KatzenPeer) Network() string {
	return "kp"
}

func (k *KatzenPeer) String() string {
	return k.User +"@" + k.Provider
}

// KatzConn implements net.Conn
type KatzConn struct {
	s Session
	lo KatzenPeer
	ro KatzenPeer
	closeCh chan bool
	rbuf []byte
}

// Read reads data from the connection.
func (k* KatzConn) Read(b []byte) (int, error) {
	if k.rbuf == nil {
		if _, ok := k.s.Messages[k.ro.String()]; ok {
			// XXX: timeouts could go here
			k.rbuf = <-k.s.Messages[k.ro.String()]
			if k.rbuf == nil {
				return 0, errors.New("Channel closed without read")
			}
		}
		return 0, errors.New("No remote peer")
	}
	switch  {
	case len(b) <= len(k.rbuf):
		l := copy(b, k.rbuf)
		k.rbuf = k.rbuf[len(b):]
		return l, nil
	case len(b) > len(k.rbuf):
		l := copy(b, k.rbuf)
		k.rbuf = nil
		return l, nil
	}
	// NOTREACHED
	return 0, errors.New("Golang doesn't do math")
}

// Write writes data to the connection.
func (k* KatzConn) Write(b []byte) (int, error) {
	switch {
	case len(b) > maxMsgLen:
		// loop and loop some more
		i := 0
		for i < len(b) {
			n := min(maxMsgLen, len(b) - i)
			bla := b[i:i+n]
			if err := k.s.minclient.SendUnreliableCiphertext(k.ro.User, k.ro.Provider, bla); err != nil {
				return i, errors.New("Failed sending to peer")
			}
			i += n
		}
		return i, nil

	case len(b) <= maxMsgLen:
		// XXX: padding or wat
		if err := k.s.minclient.SendUnreliableCiphertext(k.ro.User, k.ro.Provider, b); err != nil {
			return 0, err
		}
	}
	// NOTREACHED
	return 0, errors.New("Golang doesn't do math")
}

// Close closes the connection.
func (k* KatzConn) Close() error {
        // Any blocked Read or Write operations will be unblocked and return errors.
	return nil
}

// LocalAddr returns the local network address.
func (k* KatzConn) LocalAddr() KatzenPeer {
	return k.lo
}

// RemoteAddr returns the remote network address.
func (k* KatzConn) RemoteAddr() KatzenPeer {
	return k.ro
}

// SetDeadline sets the read and write deadlines associated with the connection.
func (k* KatzConn) SetDeadline(t time.Time) error {
	// NotImplemented
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
func (k* KatzConn) SetReadDeadline(t time.Time) error {
	// NotImplemented
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
func (k* KatzConn) SetWriteDeadline(t time.Time) error {
	// NotImplemented
	return nil
}

/*
// NewNoiseChannel does a e2e noise handshake with remote peer
func (s *Session) NewNoiseChannel(uID string) (chan []byte, chan []byte, error) {
	// should create some type to keep track of this...
	// get the peers long term identity key from somewhere
	// initialize()
	// handshake()
	prologue := []byte{0x00}
	dhKey := noise.DHKey{
		Private: s.authenticationKey.Bytes(),
		Public:  s.authenticationKey.PublicKey().Bytes(),
	}

	// finalizeHandshake()
	return nil, nil, fmt.Errorf("Handshaking with %s failed", uID)
}
*/

// New establishes a session with provider using key.
// This method will block until session is connected to the Provider.
func New(ctx context.Context, fatalErrCh chan error, logBackend *log.Backend, cfg *config.Config) (*Session, error) {
	var err error

	// create a pkiclient for our own client lookups
	// AND create a pkiclient for minclient's use
	proxyCfg := cfg.UpstreamProxyConfig()
	pkiClient, err := cfg.NewPKIClient(logBackend, proxyCfg)
	if err != nil {
		return nil, err
	}

	// create a pkiclient for minclient's use
	pkiClient2, err := cfg.NewPKIClient(logBackend, proxyCfg)
	if err != nil {
		return nil, err
	}
	pkiCacheClient := pkiclient.New(pkiClient2)

	log := logBackend.GetLogger(fmt.Sprintf("%s@%s_c", cfg.Account.User, cfg.Account.Provider))

	s := &Session{
		cfg:        cfg,
		pkiClient:  pkiClient,
		log:        log,
		fatalErrCh: fatalErrCh,
		opCh:       make(chan workerOp),
	}

	// XXX todo: replace all this with persistent data store
	s.surbIDMap = make(map[[sConstants.SURBIDLength]byte]*MessageRef)
	s.messageIDMap = make(map[[cConstants.MessageIDLength]byte]*MessageRef)
	s.replyNotifyMap = make(map[[cConstants.MessageIDLength]byte] chan []byte)
	s.Messages = make(map[string]chan []byte) // per recipient inbound messages
	s.mapLock = new(sync.Mutex)

	s.egressQueue = new(Queue)
	s.egressQueueLock = new(sync.Mutex)

	id := cfg.Account.User + "@" + cfg.Account.Provider
	basePath := filepath.Join(cfg.Proxy.DataDir, id)
	if err := cutils.MkDataDir(basePath); err != nil {
		return nil, err
	}

	err = s.loadKeys(basePath)
	if err != nil {
		return nil, err
	}

	// Configure and bring up the minclient instance.
	clientCfg := &minclient.ClientConfig{
		User:                cfg.Account.User,
		Provider:            cfg.Account.Provider,
		ProviderKeyPin:      cfg.Account.ProviderKeyPin,
		LinkKey:             s.linkKey,
		LogBackend:          logBackend,
		PKIClient:           pkiCacheClient,
		OnConnFn:            s.onConnection,
		OnMessageFn:         s.onMessage,
		OnACKFn:             s.onACK,
		OnDocumentFn:        s.onDocument,
		DialContextFn:       proxyCfg.ToDialContext("authority"),
		MessagePollInterval: time.Duration(cfg.Debug.PollingInterval) * time.Second,
		EnableTimeSync:      false, // Be explicit about it.
	}

	s.minclient, err = minclient.New(clientCfg)
	if err != nil {
		return nil, err
	}

	// block until we get the first PKI document
	// and then set our timers accordingly
	doc, err := s.awaitFirstPKIDoc(ctx)
	if err != nil {
		return nil, err
	}
	s.setTimers(doc)

	s.Go(s.worker)
	return s, nil
}

func (s *Session) awaitFirstPKIDoc(ctx context.Context) (*pki.Document, error) {
	for {
		var qo workerOp
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.HaltCh():
			s.log.Debugf("Terminating gracefully.")
			return nil, errors.New("Terminating gracefully.")
		case <-time.After(time.Duration(s.cfg.Debug.InitialMaxPKIRetrievalDelay) * time.Second):
			return nil, errors.New("Timeout failure awaiting first PKI document.")
		case qo = <-s.opCh:
		}
		switch op := qo.(type) {
		case opNewDocument:
			// Determine if PKI doc is valid. If not then abort.
			err := s.isDocValid(op.doc)
			if err != nil {
				s.log.Errorf("Aborting, PKI doc is not valid for the Loopix decoy traffic use case: %v", err)
				err := fmt.Errorf("Aborting, PKI doc is not valid for the Loopix decoy traffic use case: %v", err)
				s.fatalErrCh <- err
				return nil, err
			}
			return op.doc, nil
		default:
			continue
		}
	}
}

func (s *Session) loadKeys(basePath string) error {
	// Load link key.
	var err error
	if s.linkKey, err = config.LoadLinkKey(basePath); err != nil {
		s.log.Errorf("Failure to load link keys: %s", err)
		return err
	}
	return nil
}

// GetService returns a randomly selected service
// matching the specified service name
func (s *Session) GetService(serviceName string) (*utils.ServiceDescriptor, error) {
	doc := s.minclient.CurrentDocument()
	if doc == nil {
		return nil, errors.New("pki doc is nil")
	}
	serviceDescriptors := utils.FindServices(serviceName, doc)
	if len(serviceDescriptors) == 0 {
		return nil, errors.New("GetService failure, service not found in pki doc.")
	}
	return &serviceDescriptors[mrand.Intn(len(serviceDescriptors))], nil
}

// GetPKI returns the current PKI document.
func (s *Session) GetPKI() (*pki.Document, error) {
	doc := s.minclient.CurrentDocument()
	if doc == nil {
		return nil, errors.New("pki doc is nil")
	}
	return doc, nil
}

// OnConnection will be called by the minclient api
// upon connecting to the Provider
func (s *Session) onConnection(err error) {
	if err == nil {
		s.opCh <- opConnStatusChanged{
			isConnected: true,
		}
	}
}

// OnMessage will be called by the minclient api
// upon receiving a message
func (s *Session) onMessage(ct []byte) error {
	s.log.Debugf("OnMessage")
	// trial decrypt with each of our noise sessions.
	for uID, rx := range s.rxs {
		ctHdr, err := rx.Decrypt(nil, nil, ct[:macLen+4])
		if err != nil {
			continue // try another
		}
		s.log.Debugf("Got message for %s", uID)
		ctLen := binary.BigEndian.Uint32(ctHdr[:])
		if ctLen < macLen || ctLen > maxMsgLen {
			return errMsgSize
		}
		pt, err := rx.Decrypt(nil, nil, ct[macLen+4:])
		if err != nil {
			return err
		}
		s.Messages[uID] <- pt
		// rekey every message? hm. does this do another handshake or is it cleverer?
		rx.Rekey()
	}
	return errors.New("Failed to decrypt message")
}

// OnACK is called by the minclient api whe
// we receive an ACK message
func (s *Session) onACK(surbID *[constants.SURBIDLength]byte, ciphertext []byte) error {
	idStr := fmt.Sprintf("[%v]", hex.EncodeToString(surbID[:]))
	s.log.Infof("OnACK with SURBID %x", idStr)

	s.mapLock.Lock()
	defer s.mapLock.Unlock()

	msgRef, ok := s.surbIDMap[*surbID]
	if !ok {
		s.log.Debug("wtf, received reply with unexpected SURBID")
		return nil
	}
	replyCh, ok := s.replyNotifyMap[*msgRef.ID]
	if !ok {
		s.log.Infof("wtf, received reply with no reply notification mutex, map len is %d", len(s.replyNotifyMap))
		for key := range s.replyNotifyMap {
			s.log.Infof("key %x", key)
		}
		return nil
	}
	defer close(replyCh)
	defer delete(s.replyNotifyMap, *msgRef.ID)

	plaintext, err := sphinx.DecryptSURBPayload(ciphertext, msgRef.Key)
	if err != nil {
		s.log.Infof("SURB Reply decryption failure: %s", err)
		return err
	}
	if len(plaintext) != coreConstants.ForwardPayloadLength {
		s.log.Warningf("Discarding SURB %v: Invalid payload size: %v", idStr, len(plaintext))
		return nil
	}

	switch msgRef.SURBType {
	case cConstants.SurbTypeACK:
		// XXX: could have seperate ACK chan map, but why?
	case cConstants.SurbTypeKaetzchen, cConstants.SurbTypeInternal:
		replyCh <- plaintext[2:] // send reply
	default:
		s.log.Warningf("Discarding SURB %v: Unknown type: 0x%02x", idStr, msgRef.SURBType)
	}
	return nil
}

func (s *Session) onDocument(doc *pki.Document) {
	s.log.Debugf("onDocument(): Epoch %v", doc.Epoch)
	s.hasPKIDoc = true
	s.opCh <- opNewDocument{
		doc: doc,
	}
}

func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}
