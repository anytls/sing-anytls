package session

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/internal/pipe"
)

// Stream implements net.Conn
type Stream struct {
	id uint32

	sess *Session

	pipeR         *pipe.PipeReader
	pipeW         *pipe.PipeWriter
	writeDeadline pipe.PipeDeadline

	dieOnce sync.Once
	die     chan struct{} // closed once the stream is dead; dieErr is set before die is closed
	dieErr  error

	dieHookAccess sync.Mutex
	dieHook       func()

	reportOnce sync.Once
}

// newStream initiates a Stream struct
func newStream(id uint32, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.pipeR, s.pipeW = pipe.Pipe()
	s.writeDeadline = pipe.MakePipeDeadline()
	s.die = make(chan struct{})
	return s
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if n == 0 {
		if dieErr := s.closedErr(); dieErr != nil {
			err = dieErr
		}
	}
	return
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	select {
	case <-s.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if dieErr := s.closedErr(); dieErr != nil {
		return 0, dieErr
	}
	n, err = s.sess.writeDataFrame(s.id, b)
	return
}

// Close implements net.Conn
func (s *Stream) Close() error {
	return s.closeWithError(io.ErrClosedPipe)
}

// closeLocally only closes Stream and don't notify remote peer
func (s *Stream) closeLocally() {
	var once bool
	s.dieOnce.Do(func() {
		s.dieErr = net.ErrClosed
		close(s.die)
		s.pipeR.Close()
		once = true
	})
	if once {
		if dieHook := s.takeDieHook(); dieHook != nil {
			dieHook()
		}
	}
}

func (s *Stream) closeWithError(err error) error {
	var once bool
	s.dieOnce.Do(func() {
		s.dieErr = err
		close(s.die)
		s.pipeR.Close()
		once = true
	})
	if once {
		err := s.sess.streamClosed(s.id)
		if dieHook := s.takeDieHook(); dieHook != nil {
			dieHook()
		}
		return err
	} else {
		return s.dieErr
	}
}

// closedErr returns the error the stream died with, or nil while it is alive. dieErr is written inside dieOnce
// before die is closed, so reading it after observing the close is race-free.
func (s *Stream) closedErr() error {
	select {
	case <-s.die:
		return s.dieErr
	default:
		return nil
	}
}

// setDieHook installs the callback run once when the stream dies. The stream may already be visible to the
// session's recvLoop (and so to a concurrent Session.Close) when this is called.
func (s *Stream) setDieHook(hook func()) {
	s.dieHookAccess.Lock()
	s.dieHook = hook
	s.dieHookAccess.Unlock()
}

func (s *Stream) takeDieHook() func() {
	s.dieHookAccess.Lock()
	defer s.dieHookAccess.Unlock()
	hook := s.dieHook
	s.dieHook = nil
	return hook
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.pipeR.SetReadDeadline(t)
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// HandshakeFailure should be called when Server fail to create outbound proxy
func (s *Stream) HandshakeFailure(err error) error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && err != nil && s.sess.peerVersion >= 2 {
		f := newFrame(cmdSYNACK, s.id)
		f.data = []byte(err.Error())
		if _, err := s.sess.writeControlFrame(f); err != nil {
			return err
		}
	}
	return nil
}

// HandshakeSuccess should be called when Server success to create outbound proxy
func (s *Stream) HandshakeSuccess() error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && s.sess.peerVersion >= 2 {
		if _, err := s.sess.writeControlFrame(newFrame(cmdSYNACK, s.id)); err != nil {
			return err
		}
	}
	return nil
}
