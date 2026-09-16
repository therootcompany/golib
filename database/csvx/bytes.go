package csvx

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// URLBase64 unmarshals to bytes and marshals to a raw url base64 string
type URLBase64 []byte

func (s URLBase64) String() string {
	encoded := base64.RawURLEncoding.EncodeToString(s)
	return encoded
}

func (s URLBase64) MarshalCSV() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *URLBase64) UnmarshalCSV(src []byte) error {
	decoded, err := base64.RawURLEncoding.DecodeString(string(src))
	if err != nil {
		return fmt.Errorf("decode base64url: %w", err)
	}
	*s = decoded
	return nil
}

// MarshalJSON implements JSON marshaling to URL-safe base64.
func (s URLBase64) MarshalJSON() ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(s)
	return json.Marshal(encoded)
}

// UnmarshalJSON implements JSON unmarshaling from URL-safe base64.
func (s *URLBase64) UnmarshalJSON(data []byte) error {
	dst, err := base64.RawURLEncoding.AppendDecode([]byte{}, data)
	if err != nil {
		return fmt.Errorf("decode base64url signature: %w", err)
	}

	*s = dst
	return nil
}

// RFCBase64 unmarshals to bytes and marshals to standard base64.
type RFCBase64 []byte

func (s RFCBase64) String() string {
	encoded := base64.StdEncoding.EncodeToString(s)
	return encoded
}

// MarshalJSON implements JSON marshaling to standard base64.
func (s RFCBase64) MarshalJSON() ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(s)
	return json.Marshal(encoded)
}

// UnmarshalJSON implements JSON unmarshaling from standard base64.
func (s *RFCBase64) UnmarshalJSON(data []byte) error {
	dst, err := base64.StdEncoding.AppendDecode([]byte{}, data)
	if err != nil {
		return fmt.Errorf("decode base64 signature: %w", err)
	}

	*s = dst
	return nil
}

// Hex marshals and unmarshals bytes to a base16 (hex) string as JSON or CSV.
type Hex []byte

func (h Hex) MarshalJSON() ([]byte, error) {
	if h == nil {
		return json.Marshal(nil)
	}
	encoded := hex.EncodeToString(h)
	return json.Marshal(encoded)
}

func (h *Hex) UnmarshalJSON(src []byte) error {
	var s string
	if err := json.Unmarshal(src, &s); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("decode hex: %w", err)
	}
	*h = decoded
	return nil
}

func (h Hex) MarshalCSV() ([]byte, error) {
	return []byte(hex.EncodeToString(h)), nil
}

func (h *Hex) UnmarshalCSV(src []byte) error {
	decoded, err := hex.DecodeString(string(src))
	if err != nil {
		return fmt.Errorf("decode hex: %w", err)
	}
	*h = decoded
	return nil
}
