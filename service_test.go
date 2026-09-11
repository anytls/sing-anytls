package anytls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestUpdateUsersClosesRemovedUserSessions verifies that removing a user also
// closes the connections that user already holds. A connection is
// authenticated once, by the password hash that opens it, and then carries any
// number of streams without that password being looked at again, so replacing
// the user table alone leaves the removed user with working access.
func TestUpdateUsersClosesRemovedUserSessions(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	handler := &testHandler{connections: make(chan net.Conn, 1)}
	service, err := NewService(ServiceConfig{
		PaddingScheme: padding.DefaultPaddingScheme,
		Users:         []User{{Name: "alice", Password: "password"}},
		Handler:       handler,
		Logger:        logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	go service.NewConnection(context.Background(), serverConn, M.ParseSocksaddr("127.0.0.1:1080"), nil)

	client, err := NewClient(context.Background(), ClientConfig{
		Password: "password",
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return clientConn, nil
		},
		Logger: logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	proxyConn, err := client.CreateProxy(context.Background(), M.ParseSocksaddr("example.org:80"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.connections:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for the relayed connection")
	}

	service.UpdateUsers(nil)

	readDone := make(chan error, 1)
	go func() {
		_, readErr := proxyConn.Read(make([]byte, 1))
		readDone <- readErr
	}()
	select {
	case readErr := <-readDone:
		if readErr == nil {
			t.Fatal("expected the relayed stream to fail")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session of a removed user stayed alive")
	}
}

type testHandler struct {
	connections chan net.Conn
}

func (h *testHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.connections <- conn
}
