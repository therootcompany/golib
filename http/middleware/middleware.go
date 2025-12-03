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

// Use appends additional middleware to the chain
func (c MiddlewareChain) Use(middlewares ...Middleware) MiddlewareChain {
	newMiddlewares := make([]Middleware, len(c.middlewares), len(c.middlewares)+len(middlewares))
	copy(newMiddlewares, c.middlewares)
	newMiddlewares = append(newMiddlewares, middlewares...)

	return MiddlewareChain{middlewares: newMiddlewares}
}

type Muxer interface {
	Handle(path string, handler http.Handler)
	HandleFunc(path string, handle func(w http.ResponseWriter, r *http.Request))
}

// MiddlewareMux enables inline chaining
type MiddlewareMux struct {
	middlewares []Middleware
	mux         Muxer
}

// WithMux wraps a mux such so that Handle and HandleFunc apply the middleware chain
func WithMux(mux Muxer, middlewares ...Middleware) MiddlewareMux {
	return MiddlewareMux{
		middlewares: middlewares,
		mux:         mux,
	}
}

// With creates a new copy of the chain with the specified middleware appended
func (c MiddlewareMux) With(middlewares ...Middleware) MiddlewareMux {
	newMiddlewares := make([]Middleware, len(c.middlewares), len(c.middlewares)+len(middlewares))
	copy(newMiddlewares, c.middlewares)
	newMiddlewares = append(newMiddlewares, middlewares...)

	return MiddlewareMux{
		mux:         c.mux,
		middlewares: newMiddlewares,
	}
}

func (c MiddlewareMux) Handle(path string, handler http.Handler) {
	c.mux.Handle(path, c.handle(handler.ServeHTTP))
}

func (c MiddlewareMux) HandleFunc(path string, handler http.HandlerFunc) {
	c.mux.HandleFunc(path, c.handle(handler))
}

// Handle composes middleware with the final handler
func (c MiddlewareMux) handle(handler http.HandlerFunc) http.HandlerFunc {
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
