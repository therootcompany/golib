// Package expresscookie is a general-purpose secure-cookie package for web
// applications. Payload bytes are signed as supplied, then the signed value is
// URL-escaped for cookie transport. The format is compatible with the Node.js
// npm cookie-signature package used by Express session middleware.
//
// Payloads should be encoded by the caller (e.g., base64, JSON) before signing.
// The behavior of non-encoded plain strings is undefined; in particular, raw
// payloads containing characters such as spaces may not interoperate with
// Node.js, which uses encodeURIComponent rather than query-string escaping.
package expresscookie
