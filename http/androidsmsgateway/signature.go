package androidsmsgateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Sign returns the hex-encoded HMAC-SHA256 signature for a webhook payload.
// The message is payload concatenated with timestamp (the X-Timestamp header value).
func Sign(secretKey, payload, timestamp string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(payload + timestamp))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature verifies the HMAC-SHA256 signature of a webhook payload.
// The message is payload concatenated with timestamp (the X-Timestamp header value).
// The signature is the hex-encoded HMAC-SHA256 of that message using secretKey.
func VerifySignature(secretKey, payload, timestamp, signature string) bool {
	return hmac.Equal([]byte(Sign(secretKey, payload, timestamp)), []byte(signature))
}
