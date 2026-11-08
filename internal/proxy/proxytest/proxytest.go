// Package proxytest fakes upstream registry files for adapter tests.
package proxytest

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

// File is an upstream file of Size zero bytes, streamed in chunks the way a
// CDN sends it.
type File struct {
	Size    int
	written chan int
}

// NewFile returns an 8 MiB File. Loopback socket buffers take up to about
// 1 MiB of a response that the client never reads, so a transfer the client
// cuts short stays well under half of the file.
func NewFile() *File {
	return &File{Size: 8 << 20, written: make(chan int, 16)}
}

func (f *File) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Length", strconv.Itoa(f.Size))
	chunk := make([]byte, 32<<10)
	n := 0
	for n < f.Size {
		m, err := w.Write(chunk[:min(len(chunk), f.Size-n)])
		n += m
		if err != nil {
			break
		}
	}
	f.written <- n
}

// Written waits for the next response for f to end and returns how many
// bytes it wrote before the client hung up.
func (f *File) Written(t testing.TB) int {
	t.Helper()
	select {
	case n := <-f.written:
		return n
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream response for the file never ended")
		return 0
	}
}
