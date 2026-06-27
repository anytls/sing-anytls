package session

import (
	"bytes"
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

// TestStreamWriteOver64KiB verifies that a single Stream.Write call larger
// than the uint16 frame-length limit (65535 bytes) is correctly split into
// multiple data frames and the receiver reads back the exact same bytes.
// Before the fix, len(data) was cast to uint16, silently truncating the
// header length while the buffer.Write still copied all bytes — corrupting
// the wire and hanging the receiver.
func TestStreamWriteOver64KiB(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	var pad atomic.TypedValue[*padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad)

	clientSess := NewClient(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		return cli, nil
	}, &pad, 0, 0, 0)
	defer clientSess.Close()

	const N = 256 * 1024 // 4× max frame payload, forces splitting
	payload := make([]byte, N)
	for i := range payload {
		payload[i] = byte(i)
	}

	var got bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	serverSess := NewServerSession(srv, func(stream *Stream) {
		defer wg.Done()
		buf := make([]byte, N)
		if _, err := io.ReadFull(stream, buf); err != nil {
			t.Errorf("server ReadFull: %v", err)
			return
		}
		got.Write(buf)
	}, &pad, logger.NOP())
	go serverSess.Run()
	defer serverSess.Close()

	stream, err := clientSess.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	written, err := stream.Write(payload)
	if err != nil {
		t.Fatalf("Stream.Write: %v", err)
	}
	if written != N {
		t.Fatalf("Stream.Write returned %d, want %d", written, N)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server to read split frames")
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("server received %d bytes, want %d (and identical content)", got.Len(), N)
	}
}

func TestWriteDataFrameWritesSplitFramesContiguously(t *testing.T) {
	conn := &recordingConn{}
	sess := &Session{conn: conn}

	payload := make([]byte, maxFrameDataLen+1)
	written, err := sess.writeDataFrame(7, payload)
	if err != nil {
		t.Fatalf("writeDataFrame: %v", err)
	}
	if written != len(payload) {
		t.Fatalf("writeDataFrame returned %d, want %d", written, len(payload))
	}
	if len(conn.writes) != 1 {
		t.Fatalf("underlying conn got %d writes, want 1", len(conn.writes))
	}

	got := conn.writes[0]
	wantLen := len(payload) + 2*headerOverHeadSize
	if len(got) != wantLen {
		t.Fatalf("underlying write length = %d, want %d", len(got), wantLen)
	}
	if got[0] != cmdPSH || got[headerOverHeadSize+maxFrameDataLen] != cmdPSH {
		t.Fatal("split data frames were not serialized contiguously")
	}
}

type recordingConn struct {
	net.Conn
	writes [][]byte
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(b))
	return len(b), nil
}
