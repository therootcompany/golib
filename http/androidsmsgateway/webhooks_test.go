package androidsmsgateway_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/therootcompany/golib/http/androidsmsgateway"
)

// decodeRaw unmarshals raw JSON into a Webhook then calls Decode.
func decodeRaw(t *testing.T, raw []byte) androidsmsgateway.WebhookEvent {
	t.Helper()
	var wh androidsmsgateway.Webhook
	if err := json.Unmarshal(raw, &wh); err != nil {
		t.Fatalf("unmarshal Webhook: %v", err)
	}
	ev, err := androidsmsgateway.Decode(&wh)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return ev
}

func TestDecode_SMSReceived(t *testing.T) {
	// Verbatim example from the real gateway (includes x-signature and x-timestamp).
	raw := []byte(`{
		"deviceId": "ffffffffceb0b1db0000018e937c815b",
		"event": "sms:received",
		"id": "Ey6ECgOkVVFjz3CL48B8C",
		"payload": {
			"messageId": "abc123",
			"message": "Android is always a sweet treat!",
			"phoneNumber":"+16505551212",
			"simNumber": 1,
			"receivedAt": "2024-06-22T15:46:11.000+07:00"
		},
		"webhookId": "LreFUt-Z3sSq0JufY9uWB"
	}`)
	ev := decodeRaw(t, raw)
	got, ok := ev.(*androidsmsgateway.WebhookReceived)
	if !ok {
		t.Fatalf("expected *WebhookReceived, got %T", ev)
	}
	if got.Event != "sms:received" {
		t.Errorf("Event = %q, want sms:received", got.Event)
	}
	if got.DeviceID != "ffffffffceb0b1db0000018e937c815b" {
		t.Errorf("DeviceID = %q", got.DeviceID)
	}
	if got.WebhookID != "LreFUt-Z3sSq0JufY9uWB" {
		t.Errorf("WebhookID = %q", got.WebhookID)
	}
	if got.Payload.MessageID != "abc123" {
		t.Errorf("MessageID = %q, want abc123", got.Payload.MessageID)
	}
	if got.Payload.Message != "Android is always a sweet treat!" {
		t.Errorf("Message = %q, want \"Android is always a sweet treat!\"", got.Payload.Message)
	}
	if got.Payload.PhoneNumber != "+16505551212" {
		t.Errorf("PhoneNumber = %q, want +16505551212", got.Payload.PhoneNumber)
	}
	if got.Payload.SimNumber != 1 {
		t.Errorf("SimNumber = %d, want 1", got.Payload.SimNumber)
	}
	want, _ := time.Parse(time.RFC3339Nano, "2024-06-22T15:46:11.000+07:00")
	if !got.Payload.ReceivedAt.Equal(want) {
		t.Errorf("ReceivedAt = %v, want %v", got.Payload.ReceivedAt, want)
	}
}

func TestDecode_SMSDataReceived(t *testing.T) {
	raw := []byte(`{
		"deviceId": "ffffffffceb0b1db0000018e937c815b",
		"event": "sms:data-received",
		"id": "Ey6ECgOkVVFjz3CL48B8C",
		"payload": {
			"messageId": "abc123",
			"data": "SGVsbG8gRGF0YSBXb3JsZCE=",
			"phoneNumber": "+1234567890",
			"simNumber": 1,
			"receivedAt": "2024-06-22T15:46:11.000+07:00"
		},
		"webhookId": "LreFUt-Z3sSq0JufY9uWB"
	}`)
	ev := decodeRaw(t, raw)
	got, ok := ev.(*androidsmsgateway.WebhookDataReceived)
	if !ok {
		t.Fatalf("expected *WebhookDataReceived, got %T", ev)
	}
	if got.Event != "sms:data-received" {
		t.Errorf("Event = %q, want sms:data-received", got.Event)
	}
	if got.Payload.MessageID != "abc123" {
		t.Errorf("MessageID = %q, want abc123", got.Payload.MessageID)
	}
	if got.Payload.Data != "SGVsbG8gRGF0YSBXb3JsZCE=" {
		t.Errorf("Data = %q, want SGVsbG8gRGF0YSBXb3JsZCE=", got.Payload.Data)
	}
	if got.Payload.PhoneNumber != "+1234567890" {
		t.Errorf("PhoneNumber = %q, want +1234567890", got.Payload.PhoneNumber)
	}
	if got.Payload.SimNumber != 1 {
		t.Errorf("SimNumber = %d, want 1", got.Payload.SimNumber)
	}
	want, _ := time.Parse(time.RFC3339Nano, "2024-06-22T15:46:11.000+07:00")
	if !got.Payload.ReceivedAt.Equal(want) {
		t.Errorf("ReceivedAt = %v, want %v", got.Payload.ReceivedAt, want)
	}
}

func TestDecode_MMSReceived(t *testing.T) {
	raw := []byte(`{
		"deviceId": "ffffffffceb0b1db0000018e937c815b",
		"event": "mms:received",
		"id": "Ey6ECgOkVVFjz3CL48B8C",
		"payload": {
			"messageId": "mms_12345abcde",
			"phoneNumber": "+1234567890",
			"simNumber": 1,
			"transactionId": "T1234567890ABC",
			"subject": "Photo attachment",
			"size": 125684,
			"contentClass": "IMAGE_BASIC",
			"receivedAt": "2025-08-23T05:15:30.000+07:00"
		},
		"webhookId": "LreFUt-Z3sSq0JufY9uWB"
	}`)
	ev := decodeRaw(t, raw)
	got, ok := ev.(*androidsmsgateway.WebhookMMSReceived)
	if !ok {
		t.Fatalf("expected *WebhookMMSReceived, got %T", ev)
	}
	if got.Event != "mms:received" {
		t.Errorf("Event = %q, want mms:received", got.Event)
	}
	if got.Payload.MessageID != "mms_12345abcde" {
		t.Errorf("MessageID = %q, want mms_12345abcde", got.Payload.MessageID)
	}
	if got.Payload.PhoneNumber != "+1234567890" {
		t.Errorf("PhoneNumber = %q, want +1234567890", got.Payload.PhoneNumber)
	}
	if got.Payload.SimNumber != 1 {
		t.Errorf("SimNumber = %d, want 1", got.Payload.SimNumber)
	}
	if got.Payload.TransactionID != "T1234567890ABC" {
		t.Errorf("TransactionID = %q, want T1234567890ABC", got.Payload.TransactionID)
	}
	if got.Payload.Subject != "Photo attachment" {
		t.Errorf("Subject = %q, want Photo attachment", got.Payload.Subject)
	}
	if got.Payload.Size != 125_684 {
		t.Errorf("Size = %d, want 125684", got.Payload.Size)
	}
	if got.Payload.ContentClass != "IMAGE_BASIC" {
		t.Errorf("ContentClass = %q, want IMAGE_BASIC", got.Payload.ContentClass)
	}
	want, _ := time.Parse(time.RFC3339Nano, "2025-08-23T05:15:30.000+07:00")
	if !got.Payload.ReceivedAt.Equal(want) {
		t.Errorf("ReceivedAt = %v, want %v", got.Payload.ReceivedAt, want)
	}
}

func TestDecode_SMSSent(t *testing.T) {
	raw := []byte(`{
		"deviceId": "ffffffffceb0b1db0000018e937c815b",
		"event": "sms:sent",
		"id": "Ey6ECgOkVVFjz3CL48B8C",
		"payload": {
			"messageId": "msg-456",
			"phoneNumber": "+9998887777",
			"simNumber": 1,
			"partsCount": 1,
			"sentAt": "2026-02-18T02:05:00.000+07:00"
		},
		"webhookId": "LreFUt-Z3sSq0JufY9uWB"
	}`)
	ev := decodeRaw(t, raw)
	got, ok := ev.(*androidsmsgateway.WebhookSent)
	if !ok {
		t.Fatalf("expected *WebhookSent, got %T", ev)
	}
	if got.Event != "sms:sent" {
		t.Errorf("Event = %q, want sms:sent", got.Event)
	}
	if got.Payload.MessageID != "msg-456" {
		t.Errorf("MessageID = %q, want msg-456", got.Payload.MessageID)
	}
	if got.Payload.PhoneNumber != "+9998887777" {
		t.Errorf("PhoneNumber = %q, want +9998887777", got.Payload.PhoneNumber)
	}
	if got.Payload.SimNumber != 1 {
		t.Errorf("SimNumber = %d, want 1", got.Payload.SimNumber)
	}
	if got.Payload.PartsCount != 1 {
		t.Errorf("PartsCount = %d, want 1", got.Payload.PartsCount)
	}
	want, _ := time.Parse(time.RFC3339Nano, "2026-02-18T02:05:00.000+07:00")
	if !got.Payload.SentAt.Equal(want) {
		t.Errorf("SentAt = %v, want %v", got.Payload.SentAt, want)
	}
}

func TestDecode_SMSDelivered(t *testing.T) {
	raw := []byte(`{
		"deviceId": "ffffffffceb0b1db0000018e937c815b",
		"event": "sms:delivered",
		"id": "Ey6ECgOkVVFjz3CL48B8C",
		"payload": {
			"messageId": "msg-789",
			"phoneNumber": "+9998887777",
			"simNumber": 1,
			"deliveredAt": "2026-02-18T02:10:00.000+07:00"
		},
		"webhookId": "LreFUt-Z3sSq0JufY9uWB"
	}`)
	ev := decodeRaw(t, raw)
	got, ok := ev.(*androidsmsgateway.WebhookDelivered)
	if !ok {
		t.Fatalf("expected *WebhookDelivered, got %T", ev)
	}
	if got.Event != "sms:delivered" {
		t.Errorf("Event = %q, want sms:delivered", got.Event)
	}
	if got.Payload.MessageID != "msg-789" {
		t.Errorf("MessageID = %q, want msg-789", got.Payload.MessageID)
	}
	if got.Payload.PhoneNumber != "+9998887777" {
		t.Errorf("PhoneNumber = %q, want +9998887777", got.Payload.PhoneNumber)
	}
	if got.Payload.SimNumber != 1 {
		t.Errorf("SimNumber = %d, want 1", got.Payload.SimNumber)
	}
	want, _ := time.Parse(time.RFC3339Nano, "2026-02-18T02:10:00.000+07:00")
	if !got.Payload.DeliveredAt.Equal(want) {
		t.Errorf("DeliveredAt = %v, want %v", got.Payload.DeliveredAt, want)
	}
}

func TestDecode_SMSFailed(t *testing.T) {
	raw := []byte(`{
		"deviceId": "ffffffffceb0b1db0000018e937c815b",
		"event": "sms:failed",
		"id": "Ey6ECgOkVVFjz3CL48B8C",
		"payload": {
			"messageId": "msg-000",
			"phoneNumber": "+4445556666",
			"simNumber": 3,
			"failedAt": "2026-02-18T02:15:00.000+07:00",
			"reason": "Network error"
		},
		"webhookId": "LreFUt-Z3sSq0JufY9uWB"
	}`)
	ev := decodeRaw(t, raw)
	got, ok := ev.(*androidsmsgateway.WebhookFailed)
	if !ok {
		t.Fatalf("expected *WebhookFailed, got %T", ev)
	}
	if got.Event != "sms:failed" {
		t.Errorf("Event = %q, want sms:failed", got.Event)
	}
	if got.Payload.MessageID != "msg-000" {
		t.Errorf("MessageID = %q, want msg-000", got.Payload.MessageID)
	}
	if got.Payload.PhoneNumber != "+4445556666" {
		t.Errorf("PhoneNumber = %q, want +4445556666", got.Payload.PhoneNumber)
	}
	if got.Payload.SimNumber != 3 {
		t.Errorf("SimNumber = %d, want 3", got.Payload.SimNumber)
	}
	if got.Payload.Reason != "Network error" {
		t.Errorf("Reason = %q, want Network error", got.Payload.Reason)
	}
	want, _ := time.Parse(time.RFC3339Nano, "2026-02-18T02:15:00.000+07:00")
	if !got.Payload.FailedAt.Equal(want) {
		t.Errorf("FailedAt = %v, want %v", got.Payload.FailedAt, want)
	}
}

func TestDecode_SystemPing(t *testing.T) {
	raw := []byte(`{
		"deviceId": "ffffffffceb0b1db00000192672f2204",
		"event": "system:ping",
		"id": "mjDoocQLCsOIDra_GthuI",
		"payload": {
			"health": {
				"checks": {
					"messages:failed": {
						"description": "Failed messages for last hour",
						"observedUnit": "messages",
						"observedValue": 0,
						"status": "pass"
					},
					"connection:status": {
						"description": "Internet connection status",
						"observedUnit": "boolean",
						"observedValue": 1,
						"status": "pass"
					},
					"connection:transport": {
						"description": "Network transport type",
						"observedUnit": "flags",
						"observedValue": 4,
						"status": "pass"
					},
					"connection:cellular": {
						"description": "Cellular network type",
						"observedUnit": "index",
						"observedValue": 0,
						"status": "pass"
					},
					"battery:level": {
						"description": "Battery level in percent",
						"observedUnit": "percent",
						"observedValue": 94,
						"status": "pass"
					},
					"battery:charging": {
						"description": "Is the phone charging?",
						"observedUnit": "flags",
						"observedValue": 4,
						"status": "pass"
					}
				},
				"releaseId": 1,
				"status": "pass",
				"version": "1.0.0"
			}
		},
		"webhookId": "LreFUt-Z3sSq0JufY9uWB"
	}`)
	ev := decodeRaw(t, raw)
	got, ok := ev.(*androidsmsgateway.WebhookPing)
	if !ok {
		t.Fatalf("expected *WebhookPing, got %T", ev)
	}
	if got.Event != "system:ping" {
		t.Errorf("Event = %q, want system:ping", got.Event)
	}
	h := got.Payload.Health
	if h.Status != "pass" {
		t.Errorf("Health.Status = %q, want pass", h.Status)
	}
	if h.Version != "1.0.0" {
		t.Errorf("Health.Version = %q, want 1.0.0", h.Version)
	}
	if h.ReleaseID != 1 {
		t.Errorf("Health.ReleaseID = %d, want 1", h.ReleaseID)
	}
	c := h.Checks
	if c.BatteryLevel.ObservedValue != 94 {
		t.Errorf("BatteryLevel.ObservedValue = %v, want 94", c.BatteryLevel.ObservedValue)
	}
	if c.BatteryLevel.Status != "pass" {
		t.Errorf("BatteryLevel.Status = %q, want pass", c.BatteryLevel.Status)
	}
	if c.BatteryCharging.ObservedValue != 4 {
		t.Errorf("BatteryCharging.ObservedValue = %v, want 4", c.BatteryCharging.ObservedValue)
	}
	if c.ConnectionStatus.ObservedValue != 1 {
		t.Errorf("ConnectionStatus.ObservedValue = %v, want 1", c.ConnectionStatus.ObservedValue)
	}
	if c.ConnectionTransport.ObservedValue != 4 {
		t.Errorf("ConnectionTransport.ObservedValue = %v, want 4", c.ConnectionTransport.ObservedValue)
	}
	if c.ConnectionCellular.ObservedValue != 0 {
		t.Errorf("ConnectionCellular.ObservedValue = %v, want 0", c.ConnectionCellular.ObservedValue)
	}
	if c.MessagesFailed.ObservedValue != 0 {
		t.Errorf("MessagesFailed.ObservedValue = %v, want 0", c.MessagesFailed.ObservedValue)
	}
}

func TestDecode_UnknownEvent(t *testing.T) {
	raw := []byte(`{"deviceId":"dev1","event":"unknown:event","id":"id1","payload":{},"webhookId":"wh1"}`)
	var wh androidsmsgateway.Webhook
	if err := json.Unmarshal(raw, &wh); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, err := androidsmsgateway.Decode(&wh); err == nil {
		t.Fatal("expected error for unknown event, got nil")
	}
}

func TestSign(t *testing.T) {
	const (
		secret    = "mysecretkey"
		payload   = `{"event":"sms:received"}`
		timestamp = "1700000000"
	)

	// Independently compute the expected signature.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload + timestamp))
	want := hex.EncodeToString(mac.Sum(nil))

	got := androidsmsgateway.Sign(secret, payload, timestamp)
	if got != want {
		t.Errorf("Sign = %q, want %q", got, want)
	}
}

func TestVerifySignature(t *testing.T) {
	const (
		secret    = "mysecretkey"
		payload   = `{"event":"sms:received"}`
		timestamp = "1700000000"
	)

	sig := androidsmsgateway.Sign(secret, payload, timestamp)

	if !androidsmsgateway.VerifySignature(secret, payload, timestamp, sig) {
		t.Error("VerifySignature returned false for valid signature")
	}
	if androidsmsgateway.VerifySignature(secret, payload, timestamp, "badsignature") {
		t.Error("VerifySignature returned true for invalid signature")
	}
	if androidsmsgateway.VerifySignature("wrongkey", payload, timestamp, sig) {
		t.Error("VerifySignature returned true for wrong key")
	}
}
