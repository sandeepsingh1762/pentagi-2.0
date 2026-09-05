// Package payloads implements the Payload Engine v2: a categorized, context-aware
// payload generation library for authorized penetration testing workflows.
//
// The engine is organized around three concepts:
//
//  1. Categories: named vulnerability classes (sqli, xss, ssrf, ssti, ...) each
//     holding curated payload sets drawn from industry-standard sources
//     (PayloadsAllTheThings, OWASP testing guides, public bug-bounty methodology).
//  2. Mutators: encoding/obfuscation transforms applied to base payloads
//     (URL-encoding variants, unicode escapes, comment insertion, case
//     randomization, WAF-evasion chains).
//  3. Injection contexts: where the payload lands (query param, JSON body,
//     header, path, XML, cookie) which controls wrapping/quoting behavior.
//
// Everything is deterministic and offline: no network access, no external
// wordlist files. The package has no dependencies beyond the Go standard
// library so it can be unit-tested in isolation.
package payloads

import (
	"fmt"
	"sort"
	"strings"
)

// Category is a canonical vulnerability-class identifier.
type Category string

const (
	CategorySQLi               Category = "sqli"
	CategoryXSS                Category = "xss"
	CategorySSRF               Category = "ssrf"
	CategorySSTI               Category = "ssti"
	CategoryCmdInjection       Category = "cmd_injection"
	CategoryPathTraversal      Category = "path_traversal"
	CategoryXXE                Category = "xxe"
	CategoryLDAP               Category = "ldap_injection"
	CategoryNoSQL              Category = "nosql_injection"
	CategoryOpenRedirect       Category = "open_redirect"
	CategoryCRLF               Category = "crlf_injection"
	CategoryHeaderInjection    Category = "header_injection"
	CategoryJWT                Category = "jwt"
	CategoryDeserialization    Category = "deserialization"
	CategoryPrototypePollution Category = "prototype_pollution"
	CategoryTemplateInjection  Category = "template_injection"
	CategoryGraphQL            Category = "graphql"
	CategoryFileUpload         Category = "file_upload"
	CategorySmi                Category = "smuggling"
	CategoryCachePoisoning     Category = "cache_poisoning"
	CategoryRace               Category = "race_condition"
	CategoryAuthBypass         Category = "auth_bypass"
	CategoryIDOR               Category = "idor"
	CategoryExpression         Category = "expression_language"
	CategoryHostHeader         Category = "host_header"
)

// categoryAliases maps common synonyms used by LLMs to canonical categories.
var categoryAliases = map[string]Category{
	"sql": CategorySQLi, "sqlinjection": CategorySQLi, "sql_injection": CategorySQLi,
	"sqli": CategorySQLi, "blind_sqli": CategorySQLi, "union": CategorySQLi,
	"xss": CategoryXSS, "cross_site_scripting": CategoryXSS, "script": CategoryXSS,
	"ssrf": CategorySSRF, "server_side_request_forgery": CategorySSRF,
	"ssti": CategorySSTI, "server_side_template_injection": CategorySSTI,
	"rce": CategoryCmdInjection, "os_command_injection": CategoryCmdInjection,
	"command_injection": CategoryCmdInjection, "cmd": CategoryCmdInjection,
	"lfi": CategoryPathTraversal, "rfi": CategoryPathTraversal,
	"path_traversal": CategoryPathTraversal, "directory_traversal": CategoryPathTraversal,
	"traversal": CategoryPathTraversal, "dotdot": CategoryPathTraversal,
	"xxe": CategoryXXE, "xml_external_entity": CategoryXXE, "xml": CategoryXXE,
	"ldap": CategoryLDAP, "ldap_injection": CategoryLDAP,
	"nosql": CategoryNoSQL, "mongo": CategoryNoSQL, "mongodb": CategoryNoSQL,
	"nosql_injection": CategoryNoSQL,
	"redirect": CategoryOpenRedirect, "open_redirect": CategoryOpenRedirect,
	"url_redirect": CategoryOpenRedirect,
	"crlf": CategoryCRLF, "crlf_injection": CategoryCRLF, "response_splitting": CategoryCRLF,
	"header": CategoryHeaderInjection, "header_injection": CategoryHeaderInjection,
	"jwt": CategoryJWT, "token": CategoryJWT,
	"deserialization": CategoryDeserialization, "insecure_deserialization": CategoryDeserialization,
	"deser": CategoryDeserialization, "object_injection": CategoryDeserialization,
	"prototype_pollution": CategoryPrototypePollution, "pp": CategoryPrototypePollution,
	"template": CategoryTemplateInjection, "template_injection": CategoryTemplateInjection,
	"graphql": CategoryGraphQL, "introspection": CategoryGraphQL,
	"upload": CategoryFileUpload, "file_upload": CategoryFileUpload,
	"smuggling": CategorySmi, "request_smuggling": CategorySmi, "smi": CategorySmi,
	"cache": CategoryCachePoisoning, "cache_poisoning": CategoryCachePoisoning,
	"web_cache_poisoning": CategoryCachePoisoning, "cpdos": CategoryCachePoisoning,
	"race": CategoryRace, "race_condition": CategoryRace, "toc": CategoryRace,
	"auth_bypass": CategoryAuthBypass, "authentication_bypass": CategoryAuthBypass,
	"idor": CategoryIDOR, "bola": CategoryIDOR, "access_control": CategoryIDOR,
	"expression": CategoryExpression, "el_injection": CategoryExpression,
	"expression_language": CategoryExpression, "ognl": CategoryExpression, "spel": CategoryExpression,
	"host_header": CategoryHostHeader, "host": CategoryHostHeader,
	"password_reset_poisoning": CategoryHostHeader,
}

// contextKind describes where a payload will be placed in a request.
type contextKind string

const (
	ctxQuery  contextKind = "query"
	ctxJSON   contextKind = "json"
	ctxHeader contextKind = "header"
	ctxPath   contextKind = "path"
	ctxXML    contextKind = "xml"
	ctxCookie contextKind = "cookie"
	ctxForm   contextKind = "form"
	ctxRaw    contextKind = "raw"
)

// ParseCategory normalizes a free-form category string to a canonical Category.
// Unknown values return ok=false.
func ParseCategory(raw string) (Category, bool) {
	key := strings.ToLower(strings.TrimSpace(raw))
	key = strings.NewReplacer("-", "_", " ", "_", ".", "", "/", "").Replace(key)
	if cat, ok := categoryAliases[key]; ok {
		return cat, true
	}
	cat := Category(key)
	if _, exists := categoryPayloads[cat]; exists {
		return cat, true
	}
	return "", false
}

// Categories returns all canonical category names sorted alphabetically.
func Categories() []string {
	out := make([]string, 0, len(categoryPayloads))
	for cat := range categoryPayloads {
		out = append(out, string(cat))
	}
	sort.Strings(out)
	return out
}

// CategoryInfo describes a category for tooling/LLM consumption.
type CategoryInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Payloads    int    `json:"payload_count"`
}

// Describe returns metadata for every category.
func Describe() []CategoryInfo {
	out := make([]CategoryInfo, 0, len(categoryPayloads))
	for cat, set := range categoryPayloads {
		out = append(out, CategoryInfo{
			Name:        string(cat),
			Description: set.description,
			Payloads:    len(set.base),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// payloadSet holds the curated base payloads plus per-category metadata.
type payloadSet struct {
	description string
	base        []string
}

// Get returns the base payload list for a category.
func (c Category) Get() ([]string, error) {
	set, ok := categoryPayloads[c]
	if !ok {
		return nil, fmt.Errorf("unknown payload category: %s", c)
	}
	return set.base, nil
}

// ForContext adapts a payload to the injection context: JSON string escaping,
// header-safe crlf-stripping, XML entity quoting, etc.
func ForContext(p string, context string) string {
	switch strings.ToLower(strings.TrimSpace(context)) {
	case string(ctxJSON):
		return jsonEscape(p)
	case string(ctxHeader), string(ctxCookie):
		// headers cannot carry raw CR/LF: the caller must use the dedicated
		// crlf category to test header injection deliberately
		return strings.NewReplacer("\r", "%0d", "\n", "%0a").Replace(p)
	case string(ctxXML):
		return xmlEscape(p)
	case string(ctxPath):
		return strings.ReplaceAll(p, " ", "%20")
	default:
		return p
	}
}

// jsonEscape produces a JSON-string-safe body (without surrounding quotes).
func jsonEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// xmlEscape escapes characters that would break XML attribute/text context.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;",
	)
	return r.Replace(s)
}
