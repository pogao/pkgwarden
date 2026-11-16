// Package connpool is the HTTP transport for pkgwarden's upstream requests.
// It keeps its own HTTP/2 connections, one set per host, so that a request
// past every connection's stream limit waits for a free stream or for a
// connection already being dialed. net/http would instead dial a connection
// for that one request and then usually throw it away.
package connpool

import (
	"cmp"
	"container/list"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Transport is an http.RoundTripper. HTTPS requests go over HTTP/2
// connections it dials with its base transport and keeps until they idle
// out or the server closes them. Plain http requests, and every request to
// a host whose first response came over HTTP/1, go through the base
// transport itself.
type Transport struct {
	base *http.Transport

	mu    sync.Mutex
	hosts map[string]*host
}

// New returns a Transport that dials with base. base must allow HTTP/2, as
// ForceAttemptHTTP2 does. Its Proxy, TLSHandshakeTimeout,
// ResponseHeaderTimeout, and IdleConnTimeout apply to the pooled
// connections too.
func New(base *http.Transport) *Transport {
	return &Transport{base: base, hosts: make(map[string]*host)}
}

const (
	maxRetries  = 2
	redialAfter = time.Second
)

var errHTTP1 = errors.New("connpool: host speaks HTTP/1")

// RoundTrip sends req. Like net/http's own HTTP/2 client, it sends req
// again when the server cannot have processed it, as long as the body is
// empty or GetBody can replay it.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return t.base.RoundTrip(req)
	}
	h := t.host(req.URL)
	for attempt := 0; ; attempt++ {
		if h.http1.Load() {
			return t.base.RoundTrip(req)
		}
		c, err := h.acquire(req.Context())
		if err == errHTTP1 {
			continue
		}
		if err != nil {
			if req.Body != nil {
				req.Body.Close()
			}
			return nil, err
		}
		resp, err := c.cc.RoundTrip(req)
		if c.phase() != settled {
			resp = h.settle(c, resp, err)
		}
		if err == nil {
			return resp, nil
		}
		if attempt == maxRetries || req.Context().Err() != nil || !neverProcessed(err) {
			return nil, err
		}
		next, ok := rewind(req)
		if !ok {
			return nil, err
		}
		req = next
	}
}

func (t *Transport) host(u *url.URL) *host {
	addr := net.JoinHostPort(u.Hostname(), cmp.Or(u.Port(), "443"))
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.hosts[addr]
	if h == nil {
		h = &host{base: t.base, addr: addr, wake: make(chan struct{}, 1)}
		t.hosts[addr] = h
		go h.dispatchOnWake()
	}
	return h
}

type host struct {
	base  *http.Transport
	addr  string
	http1 atomic.Bool
	wake  chan struct{}

	mu          sync.Mutex
	conns       []*conn
	waiters     queue
	dialing     int
	lastLimit   int
	noDialUntil time.Time
}

type queue struct {
	l list.List
	n atomic.Int64
}

type waiter struct {
	ready chan grant
	elem  *list.Element
}

type grant struct {
	c   *conn
	err error
}

func (q *queue) push(w *waiter) {
	w.elem = q.l.PushBack(w)
	q.n.Add(1)
}

// grantNext hands g to the oldest waiter. ready is buffered and receives
// exactly one grant, so the send never blocks.
func (q *queue) grantNext(g grant) {
	w := q.l.Remove(q.l.Front()).(*waiter)
	w.elem = nil
	q.n.Add(-1)
	w.ready <- g
}

func (q *queue) remove(w *waiter) bool {
	if w.elem == nil {
		return false
	}
	q.l.Remove(w.elem)
	w.elem = nil
	q.n.Add(-1)
	return true
}

func (q *queue) len() int { return q.l.Len() }

// waitingUnlocked reads the queue's length without host.mu, for the state
// hook, which must not take it.
func (q *queue) waitingUnlocked() bool { return q.n.Load() > 0 }

// Until the server's SETTINGS frame arrives, net/http's Available counts a
// placeholder limit of 100 streams rather than the server's limit, and the
// server refuses streams past its real limit.
type phase uint32

const (
	fresh phase = iota
	probing
	settled
)

type conn struct {
	cc *http.ClientConn
	p  atomic.Uint32
}

func (c *conn) phase() phase           { return phase(c.p.Load()) }
func (c *conn) setPhaseLocked(p phase) { c.p.Store(uint32(p)) }

func (h *host) acquire(ctx context.Context) (*conn, error) {
	h.mu.Lock()
	if h.waiters.len() == 0 {
		if c := h.reserveOldestLocked(); c != nil {
			h.mu.Unlock()
			return c, nil
		}
	}
	w := &waiter{ready: make(chan grant, 1)}
	h.waiters.push(w)
	h.dispatchLocked()
	h.mu.Unlock()

	select {
	case g := <-w.ready:
		return g.c, g.err
	case <-ctx.Done():
	}
	h.mu.Lock()
	queued := h.waiters.remove(w)
	h.mu.Unlock()
	if !queued {
		if g := <-w.ready; g.c != nil {
			h.release(g.c)
		}
	}
	return nil, context.Cause(ctx)
}

func (h *host) reserveOldestLocked() *conn {
	for _, c := range h.conns {
		p := c.phase()
		if p == probing || c.cc.Reserve() != nil {
			continue
		}
		if p == fresh {
			c.setPhaseLocked(probing)
		}
		return c
	}
	return nil
}

func (h *host) release(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c.cc.Release()
	if c.phase() == probing {
		c.setPhaseLocked(fresh)
	}
	h.dispatchLocked()
}

func (h *host) dispatchLocked() {
	h.pruneLocked()
	if h.http1.Load() {
		for h.waiters.len() > 0 {
			h.waiters.grantNext(grant{err: errHTTP1})
		}
		return
	}
	for h.waiters.len() > 0 {
		c := h.reserveOldestLocked()
		if c == nil {
			break
		}
		h.waiters.grantNext(grant{c: c})
	}
	short := h.waiters.len() - h.streamsComingLocked()
	if short <= 0 || time.Now().Before(h.noDialUntil) {
		return
	}
	n := 1
	if h.lastLimit > 0 {
		n = (short + h.lastLimit - 1) / h.lastLimit
	}
	h.dialing += n
	for range n {
		go h.dial()
	}
}

func (h *host) pruneLocked() {
	h.conns = slices.DeleteFunc(h.conns, func(c *conn) bool { return c.cc.Err() != nil })
}

// streamsComingLocked counts the streams that dials in flight and unsettled
// connections will offer once they settle. With no limit known yet, it is
// unbounded, so one dial covers every waiter until its probe reports.
func (h *host) streamsComingLocked() int {
	unsettled, probes := h.dialing, 0
	for _, c := range h.conns {
		switch c.phase() {
		case fresh:
			unsettled++
		case probing:
			unsettled++
			probes++
		}
	}
	switch {
	case unsettled == 0:
		return 0
	case h.lastLimit == 0:
		return math.MaxInt
	}
	return unsettled*h.lastLimit - probes
}

func (h *host) dial() {
	cc, err := h.base.NewClientConn(context.Background(), "https", h.addr)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dialing--
	if err != nil {
		h.dialFailedLocked(err)
		return
	}
	h.conns = append(h.conns, &conn{cc: cc})
	cc.SetStateHook(func(cc *http.ClientConn) {
		if h.waiters.waitingUnlocked() || cc.Err() != nil {
			h.kick()
		}
	})
	h.dispatchLocked()
}

func (h *host) dialFailedLocked(err error) {
	h.pruneLocked()
	if h.dialing == 0 && len(h.conns) == 0 {
		for h.waiters.len() > 0 {
			h.waiters.grantNext(grant{err: err})
		}
		return
	}
	h.noDialUntil = time.Now().Add(redialAfter)
	time.AfterFunc(redialAfter, h.kick)
}

// net/http runs the state hook, which calls kick, synchronously inside
// ClientConn.Reserve, and reserveOldestLocked calls Reserve with host.mu
// held. So kick only signals dispatchOnWake.
func (h *host) kick() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

func (h *host) dispatchOnWake() {
	for range h.wake {
		h.mu.Lock()
		h.dispatchLocked()
		h.mu.Unlock()
	}
}

// An HTTP/2 response settles c, because the server sends its SETTINGS
// before any response (RFC 9113, section 3.4).
func (h *host) settle(c *conn, resp *http.Response, err error) *http.Response {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case err != nil:
		c.setPhaseLocked(fresh)
	case resp.ProtoMajor == 1:
		h.http1.Store(true)
		h.conns = slices.DeleteFunc(h.conns, func(x *conn) bool { return x == c })
		resp.Body = closeConnBody{resp.Body, c.cc}
	default:
		c.setPhaseLocked(settled)
		if n := h.streamLimitLocked(c.cc); n > 0 {
			h.lastLimit = n
		}
	}
	h.dispatchLocked()
	return resp
}

// streamLimitLocked reads Available plus InFlight. A stream can finish
// between the reads, but with host.mu held none can start, so two equal
// InFlight reads bracket a stable count. net/http reports Available as 0
// once a connection takes no new streams, as after GOAWAY, so the limit is
// then unknown and streamLimitLocked returns 0.
func (h *host) streamLimitLocked(cc *http.ClientConn) int {
	for {
		f := cc.InFlight()
		a := cc.Available()
		if a == 0 {
			return 0
		}
		if cc.InFlight() == f {
			return a + f
		}
	}
}

type closeConnBody struct {
	io.ReadCloser
	cc *http.ClientConn
}

func (b closeConnBody) Close() error {
	err := b.ReadCloser.Close()
	b.cc.Close()
	return err
}

// neverProcessed reports whether err is one that net/http's HTTP/2 client
// resends itself, because the server cannot have processed the request
// (canRetryError in net/http/internal/http2/transport.go). The errors are
// unexported, so their text is matched.
func neverProcessed(err error) bool {
	s := err.Error()
	return s == "http2: client conn not usable" ||
		s == "http2: Transport received Server's graceful shutdown GOAWAY" ||
		strings.HasPrefix(s, "stream error: ") && strings.Contains(s, "; REFUSED_STREAM")
}

func rewind(req *http.Request) (*http.Request, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	r := *req
	r.Body = body
	return &r, true
}
