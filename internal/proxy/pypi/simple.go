package pypi

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"strconv"
	"strings"
	"time"
)

const (
	jsonType = "application/vnd.pypi.simple.v1+json"
	htmlType = "application/vnd.pypi.simple.v1+html"
)

// served maps each media type a client may ask for to the type we answer with.
var served = map[string]string{
	jsonType: jsonType,
	"application/vnd.pypi.simple.latest+json": jsonType,
	htmlType: htmlType,
	"application/vnd.pypi.simple.latest+html": htmlType,
	"text/html": "text/html",
	"*/*":       "text/html",
}

// negotiate picks the response type with the highest q value in accept,
// the first listed winning ties, as PEP 691 describes. Without a usable
// Accept header it answers with a PEP 503 HTML page.
func negotiate(accept string) string {
	best, bestQ := "text/html", 0.0
	for part := range strings.SplitSeq(accept, ",") {
		mt, params, err := mime.ParseMediaType(part)
		if err != nil {
			continue
		}
		t, ok := served[mt]
		if !ok {
			continue
		}
		q := 1.0
		if s, ok := params["q"]; ok {
			if q, err = strconv.ParseFloat(s, 64); err != nil {
				continue
			}
		}
		if q > bestQ {
			best, bestQ = t, q
		}
	}
	return best
}

// index is a project page listing the files of allowed releases.
type index struct {
	name     string
	versions []string
	links    []link
}

type link struct {
	file
	href string
}

type jsonFile struct {
	Filename       string            `json:"filename"`
	URL            string            `json:"url"`
	Hashes         map[string]string `json:"hashes"`
	RequiresPython *string           `json:"requires-python"`
	Yanked         any               `json:"yanked"`
	Size           int64             `json:"size"`
	UploadTime     string            `json:"upload-time,omitempty"`
	CoreMetadata   any               `json:"core-metadata"`
	// DistInfoMetadata is the pre-PEP 714 name older clients still read.
	DistInfoMetadata any `json:"dist-info-metadata"`
}

func (ix *index) writeJSON(w io.Writer) {
	doc := struct {
		Meta struct {
			APIVersion string `json:"api-version"`
		} `json:"meta"`
		Name     string     `json:"name"`
		Versions []string   `json:"versions"`
		Files    []jsonFile `json:"files"`
	}{Name: ix.name, Versions: ix.versions, Files: []jsonFile{}}
	doc.Meta.APIVersion = "1.1"
	if doc.Versions == nil {
		doc.Versions = []string{}
	}
	for _, l := range ix.links {
		f := jsonFile{Filename: l.Filename, URL: l.href, Hashes: map[string]string{}, Yanked: false, Size: l.Size, CoreMetadata: false}
		if l.Digests.SHA256 != "" {
			f.Hashes["sha256"] = l.Digests.SHA256
		}
		if l.RequiresPython != "" {
			f.RequiresPython = &l.RequiresPython
		}
		if l.Yanked {
			f.Yanked = true
			if l.YankedReason != "" {
				f.Yanked = l.YankedReason
			}
		}
		if !l.UploadTime.IsZero() {
			f.UploadTime = l.UploadTime.UTC().Format(time.RFC3339Nano)
		}
		if l.CoreMetadata != "" {
			f.CoreMetadata = map[string]string{"sha256": string(l.CoreMetadata)}
		}
		f.DistInfoMetadata = f.CoreMetadata
		doc.Files = append(doc.Files, f)
	}
	json.NewEncoder(w).Encode(doc)
}

func (ix *index) writeHTML(w io.Writer) {
	var b strings.Builder
	name := html.EscapeString(ix.name)
	fmt.Fprintf(&b, "<!DOCTYPE html>\n<html>\n  <head>\n    <meta name=\"pypi:repository-version\" content=\"1.1\">\n    <title>Links for %s</title>\n  </head>\n  <body>\n    <h1>Links for %s</h1>\n", name, name)
	for _, l := range ix.links {
		href := l.href
		if l.Digests.SHA256 != "" {
			href += "#sha256=" + l.Digests.SHA256
		}
		fmt.Fprintf(&b, "    <a href=\"%s\"", html.EscapeString(href))
		if l.RequiresPython != "" {
			fmt.Fprintf(&b, " data-requires-python=\"%s\"", html.EscapeString(l.RequiresPython))
		}
		if l.Yanked {
			fmt.Fprintf(&b, " data-yanked=\"%s\"", html.EscapeString(l.YankedReason))
		}
		if l.CoreMetadata != "" {
			fmt.Fprintf(&b, " data-core-metadata=\"sha256=%[1]s\" data-dist-info-metadata=\"sha256=%[1]s\"", html.EscapeString(string(l.CoreMetadata)))
		}
		fmt.Fprintf(&b, ">%s</a><br />\n", html.EscapeString(l.Filename))
	}
	b.WriteString("  </body>\n</html>\n")
	io.WriteString(w, b.String())
}
