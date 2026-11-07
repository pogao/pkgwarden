package advisory

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const userAgent = "pkgwarden"

var errTooLarge = errors.New("response body too large")

// send performs req and returns the response when its status is 2xx. The
// caller owns the returned body.
func send(client *http.Client, req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Redacted(), resp.Status, strings.TrimSpace(string(snippet)))
	}
	return resp, nil
}

// readBody reads at most limit bytes of a successful response to req.
func readBody(client *http.Client, req *http.Request, limit int64) ([]byte, http.Header, error) {
	resp, err := send(client, req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(capped(resp.Body, limit))
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: %w", req.Method, req.URL.Redacted(), err)
	}
	return body, resp.Header, nil
}

// capped wraps r so that reading more than limit bytes fails with errTooLarge
// instead of silently truncating.
func capped(r io.Reader, limit int64) io.Reader {
	return &cappedReader{r: r, left: limit}
}

type cappedReader struct {
	r    io.Reader
	left int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return n, fmt.Errorf("%w: limit exceeded", errTooLarge)
	}
	return n, err
}
