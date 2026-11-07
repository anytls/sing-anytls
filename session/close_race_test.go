package session

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

// The races below only show up when nothing else orders the two goroutines. A kernel socket would (the race
// detector treats the runtime fd mutex as synchronisation), which is why chanConn is used: each direction is an
// independent channel, like the two halves of a real TLS connection that only share the peer.

// TestStreamWriteDuringSessionClose: the peer goes away while the application keeps writing to a stream.
// recvLoop fails -> Session.Close -> Stream.closeLocally writes dieErr, while Stream.Write reads it on the
// application goroutine with no synchronisation. Run with -race.
func TestStreamWriteDuringSessionClose(t *testing.T) {
	for i := 0; i < 50; i++ {
		cli, srv := chanPipe()
		pad := newTestPad()
		serverSess := NewServerSession(srv, func(stream *Stream) {
			go io.Copy(io.Discard, stream)
		}, pad, logger.NOP())
		go serverSess.Run()

		clientSess := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
			return cli, nil
		}, pad, 0, 0, 0, false)
		stream, err := clientSess.CreateStream(context.Background())
		if err != nil {
			t.Fatalf("CreateStream: %v", err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 512)
			for {
				if _, err := stream.Write(buf); err != nil {
					return
				}
			}
		}()
		time.Sleep(time.Millisecond)
		_ = srv.Close() // peer drops the connection
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("writer did not observe the closed session")
		}
		_ = clientSess.Close()
		_ = serverSess.Close()
	}
}

// TestCreateStreamDuringSessionClose: Client.CreateStream assigns stream.dieHook after OpenStream has already
// registered the stream in the session, while a concurrent Session.Close -> closeLocally reads and clears it.
// Run with -race.
func TestCreateStreamDuringSessionClose(t *testing.T) {
	for i := 0; i < 50; i++ {
		cli, srv := chanPipe()
		pad := newTestPad()
		serverSess := NewServerSession(srv, func(stream *Stream) { go io.Copy(io.Discard, stream) }, pad, logger.NOP())
		go serverSess.Run()
		clientSess := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
			return cli, nil
		}, pad, 0, 0, 0, true)
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = clientSess.CreateStream(context.Background())
			}()
		}
		_ = srv.Close()
		wg.Wait()
		_ = clientSess.Close()
		_ = serverSess.Close()
	}
}

func newTestPad() *atomic.TypedValue[*padding.PaddingFactory] {
	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)
	return &pad
}

// chanConn: one end of an in-memory duplex connection with independent, buffered directions.
type chanConn struct {
	in, out   chan []byte
	pending   []byte
	closed    chan struct{}
	peer      *chanConn
	closeOnce sync.Once
}

func chanPipe() (*chanConn, *chanConn) {
	a2b, b2a := make(chan []byte, 1024), make(chan []byte, 1024)
	a := &chanConn{in: b2a, out: a2b, closed: make(chan struct{})}
	b := &chanConn{in: a2b, out: b2a, closed: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

func (c *chanConn) Read(p []byte) (int, error) {
	if len(c.pending) == 0 {
		select {
		case b := <-c.in:
			c.pending = b
		case <-c.closed:
			return 0, io.EOF
		case <-c.peer.closed:
			return 0, io.EOF
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *chanConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	case <-c.peer.closed:
		return 0, io.ErrClosedPipe
	case c.out <- append([]byte(nil), p...):
		return len(p), nil
	}
}

func (c *chanConn) Close() error                       { c.closeOnce.Do(func() { close(c.closed) }); return nil }
func (c *chanConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *chanConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *chanConn) SetDeadline(t time.Time) error      { return nil }
func (c *chanConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *chanConn) SetWriteDeadline(t time.Time) error { return nil }
