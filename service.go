package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Service struct {
	users           map[[32]byte]string
	padding         atomic.TypedValue[*padding.PaddingFactory]
	handler         N.TCPConnectionHandlerEx
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger

	sessionAccess sync.Mutex
	sessions      map[*session.Session]string
}

type ServiceConfig struct {
	PaddingScheme   []byte
	Users           []User
	Handler         N.TCPConnectionHandlerEx
	FallbackHandler N.TCPConnectionHandlerEx
	Logger          logger.ContextLogger
}

type User struct {
	Name     string
	Password string
}

func NewService(config ServiceConfig) (*Service, error) {
	service := &Service{
		handler:         config.Handler,
		fallbackHandler: config.FallbackHandler,
		logger:          config.Logger,
		users:           make(map[[32]byte]string),
		sessions:        make(map[*session.Session]string),
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}

	for _, user := range config.Users {
		service.users[sha256.Sum256([]byte(user.Password))] = user.Name
	}

	if !padding.UpdatePaddingScheme(config.PaddingScheme, &service.padding) {
		return nil, errors.New("incorrect padding scheme format")
	}

	return service, nil
}

func (s *Service) UpdateUsers(users []User) {
	u := make(map[[32]byte]string)
	for _, user := range users {
		u[sha256.Sum256([]byte(user.Password))] = user.Name
	}
	s.users = u
	s.closeRemovedSessions(users)
}

// trackSession registers an authenticated session, so that a later UpdateUsers
// can revoke it.
func (s *Service) trackSession(userSession *session.Session, user string) {
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	s.sessions[userSession] = user
}

func (s *Service) untrackSession(userSession *session.Session) {
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	delete(s.sessions, userSession)
}

// closeRemovedSessions closes the sessions of users that are gone from the new
// user table. A connection is authenticated once, by the password hash that
// opens it, and then carries any number of streams without that password being
// looked at again, so dropping a user from the table does not by itself revoke
// the access that user already has.
//
// Victims are collected under the lock and closed after it is released, so that
// Session.Close never runs with the session lock held.
func (s *Service) closeRemovedSessions(users []User) {
	names := make(map[string]struct{}, len(users))
	for _, user := range users {
		names[user.Name] = struct{}{}
	}
	s.sessionAccess.Lock()
	var removed []*session.Session
	for userSession, user := range s.sessions {
		if _, stillValid := names[user]; !stillValid {
			removed = append(removed, userSession)
		}
	}
	s.sessionAccess.Unlock()
	for _, userSession := range removed {
		userSession.Close()
	}
}

// NewConnection `conn` should be plaintext
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(conn)
	if err != nil {
		return err
	}
	conn = bufio.NewCachedConn(conn, b)

	by, err := b.ReadBytes(32)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, err, onClose)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], by)
	user, loaded := s.users[passwordSha256]
	if !loaded {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.New("unknown user password"), onClose)
	}
	ctx = auth.ContextWithUser(ctx, user)
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.Extend(err, "read padding length"), onClose)
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			return s.fallback(ctx, conn, source, E.Extend(err, "read padding"), onClose)
		}
	}

	session := session.NewServerSession(conn, func(stream *session.Stream) {
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			s.logger.ErrorContext(ctx, "ReadAddrPort:", err)
			return
		}

		s.handler.NewConnectionEx(ctx, stream, source, destination, onClose)
	}, &s.padding, s.logger)
	s.trackSession(session, user)
	defer s.untrackSession(session)
	session.Run()
	session.Close()
	return nil
}

func (s *Service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}
