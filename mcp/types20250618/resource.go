package mcptypes

import "context"

// ---------------------------------------------------------------------------
// Resource definition
// ---------------------------------------------------------------------------

// Resource describes an MCP resource.
//
// Differences from mcp-go:
//   - Omits: Annotated embed, Icons, Size fields. Add when needed.
type Resource struct {
	Meta        *Meta        `json:"_meta,omitempty"`
	URI         string       `json:"uri"`
	Name        string       `json:"name"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	MIMEType    string       `json:"mimeType,omitempty"`
	Annotations *Annotations `json:"annotations,omitempty"`
	Size        *int64       `json:"size,omitempty"`
}

// Annotations provide optional hints about a resource or content item.
type Annotations struct {
	Audience     []string `json:"audience,omitempty"`
	Priority     *float64 `json:"priority,omitempty"`
	LastModified string   `json:"lastModified,omitempty"`
}

// ResourceTemplate describes a parameterized resource URI.
type ResourceTemplate struct {
	Meta        *Meta        `json:"_meta,omitempty"`
	URITemplate string       `json:"uriTemplate"`
	Name        string       `json:"name"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	MIMEType    string       `json:"mimeType,omitempty"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

// ---------------------------------------------------------------------------
// Resource contents
// ---------------------------------------------------------------------------

// ResourceContents represents the contents of a resource.
// Meta may carry _meta.ui (CSP, permissions) per the MCP Apps spec;
// content-item _meta takes precedence over resource-listing _meta.
type ResourceContents struct {
	Meta     *Meta  `json:"_meta,omitempty"`
	URI      string `json:"uri"`
	MIMEType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"` // base64-encoded
}

// TextResourceContents represents text resource contents.
type TextResourceContents = ResourceContents

// ---------------------------------------------------------------------------
// Resource request
// ---------------------------------------------------------------------------

// ReadResourceRequest is the request for reading a resource.
type ReadResourceRequest struct {
	Method string
	Params ReadResourceParams
}

// ReadResourceParams contains the resource read parameters.
type ReadResourceParams struct {
	URI string `json:"uri"`
}

// ResourceHandler is the function signature for resource read handlers.
type ResourceHandler func(ctx context.Context, req ReadResourceRequest) ([]ResourceContents, error)
