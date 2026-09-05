package payloads

import (
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
)

// Mutator is a single payload transform.
type Mutator struct {
	Name        string
	Description string
	Fn          func(string) string
}

// EncodeStyle names the built-in mutation families.
const (
	MutURL             = "url_encode"
	MutDoubleURL       = "double_url_encode"
	MutUnicode         = "unicode_escape"
	MutHTMLEntity      = "html_entity"
	MutHex             = "hex_encode"
	MutCaseRandom      = "case_random"
	MutCommentInsert   = "comment_insert"
	MutNullByte        = "null_byte"
	MutNewlineEscape   = "newline_escape"
	MutIFSSubstitution = "ifs_substitution"
	MutJSONEscape      = "json_escape"
	MutBase64          = "base64"
)

// Mutators returns every built-in mutator in a stable order.
func Mutators() []Mutator {
	return []Mutator{
		{Name: MutURL, Description: "percent-encode reserved characters", Fn: mutURLEncode},
		{Name: MutDoubleURL, Description: "double percent-encode (WAF normalization confusion)", Fn: mutDoubleURLEncode},
		{Name: MutUnicode, Description: "\\u escape sequences for letters/digits", Fn: mutUnicodeEscape},
		{Name: MutHTMLEntity, Description: "numeric HTML entities for < > \" '", Fn: mutHTMLEntity},
		{Name: MutHex, Description: "0x hex encoding of bytes", Fn: mutHex},
		{Name: MutCaseRandom, Description: "random-case folding (tag/keyword filter confusion)", Fn: mutCaseRandom},
		{Name: MutCommentInsert, Description: "SQL/HTML comment insertion inside keywords", Fn: mutCommentInsert},
		{Name: MutNullByte, Description: "append/inline null byte variants", Fn: mutNullByte},
		{Name: MutNewlineEscape, Description: "CR/LF (%0d/%0a) insertion", Fn: mutNewline},
		{Name: MutIFSSubstitution, Description: "${IFS} space substitution for command contexts", Fn: mutIFS},
		{Name: MutJSONEscape, Description: "JSON string escaping", Fn: jsonEscape},
		{Name: MutBase64, Description: "standard base64 encoding", Fn: mutBase64},
	}
}

// GetMutator looks up a mutator by name.
func GetMutator(name string) (Mutator, error) {
	for _, m := range Mutators() {
		if m.Name == name {
			return m, nil
		}
	}
	return Mutator{}, fmt.Errorf("unknown mutator: %s", name)
}

func mutURLEncode(s string) string {
	return url.QueryEscape(s)
}

func mutDoubleURLEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(s))
}

func mutUnicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			fmt.Fprintf(&b, `\u%04x`, r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func mutHTMLEntity(s string) string {
	var b strings.Builder
	repl := map[rune]string{'<': "&#60;", '>': "&#62;", '"': "&#34;", '\'': "&#39;", '&': "&#38;"}
	for _, r := range s {
		if v, ok := repl[r]; ok {
			b.WriteString(v)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func mutHex(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "0x%02x", s[i])
	}
	return b.String()
}

var caseRand = rand.New(rand.NewSource(1)) // deterministic default source

func mutCaseRandom(s string) string {
	var b strings.Builder
	for _, r := range s {
		if caseRand.Intn(2) == 0 {
			b.WriteString(strings.ToLower(string(r)))
		} else {
			b.WriteString(strings.ToUpper(string(r)))
		}
	}
	return b.String()
}

var keywordCommentRe = regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|or|and|script|onerror|onload|alert|exec)`)

func mutCommentInsert(s string) string {
	return keywordCommentRe.ReplaceAllStringFunc(s, func(kw string) string {
		if len(kw) < 2 {
			return kw
		}
		mid := len(kw) / 2
		return kw[:mid] + "/**/" + kw[mid:]
	})
}

func mutNullByte(s string) string {
	return []string{s + "%00", s + "\x00", "%00" + s}[0]
}

func mutNewline(s string) string {
	return s + "%0d%0a"
}

func mutIFS(s string) string {
	return strings.ReplaceAll(s, " ", "${IFS}")
}

func mutBase64(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var b strings.Builder
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], data[i:])
		v := uint32(chunk[0])<<16 | uint32(chunk[1])<<8 | uint32(chunk[2])
		b.WriteByte(alphabet[(v>>18)&0x3f])
		b.WriteByte(alphabet[(v>>12)&0x3f])
		if n > 1 {
			b.WriteByte(alphabet[(v>>6)&0x3f])
		} else {
			b.WriteByte('=')
		}
		if n > 2 {
			b.WriteByte(alphabet[v&0x3f])
		} else {
			b.WriteByte('=')
		}
	}
	return b.String()
}
