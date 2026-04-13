// Authored in 2026 by AJ ONeal <aj@therootcompany.com>, assisted by AI.
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

// Package xhubsig verifies X-Hub-Signature-256 HMAC-SHA256 webhook signatures
// and provides HTTP middleware for Go servers. Errors are returned in the
// format requested by the Accept header (TSV by default; JSON, CSV, or
// Markdown on request).
package xhubsig
