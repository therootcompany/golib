// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

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
