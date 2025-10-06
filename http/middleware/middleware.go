// Authored in 2025 by AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

package middleware

import (
	"net/http"
	"slices"
)

// Middleware receives and returns and http.HandlerFunc
type Middleware func(http.HandlerFunc) http.HandlerFunc

// MiddlewareChain enables inline chaining
type MiddlewareChain struct {
	middlewares []Middleware
}

// New creates a reusable MiddlewareChain with 0 or more middleware
func New(middlewares ...Middleware) MiddlewareChain {
	return MiddlewareChain{middlewares: middlewares}
}

// Use appends additional middleware to the chain
func (c MiddlewareChain) Use(middlewares ...Middleware) MiddlewareChain {
	newMiddlewares := make([]Middleware, len(c.middlewares), len(c.middlewares)+len(middlewares))
	copy(newMiddlewares, c.middlewares)
	newMiddlewares = append(newMiddlewares, middlewares...)

	return MiddlewareChain{middlewares: newMiddlewares}
}

// Handle composes middleware with the final handler
func (c MiddlewareChain) Handle(handler http.HandlerFunc) http.HandlerFunc {
	if handler == nil {
		panic("mw.New(...).Use(...).Handle(-->this<--) requires a handler")
	}

	middlewares := make([]Middleware, len(c.middlewares))
	copy(middlewares, c.middlewares)
	slices.Reverse(middlewares)

	// Apply middleware in forward order
	result := handler
	for _, m := range middlewares {
		result = m(result)
	}

	return result
}
