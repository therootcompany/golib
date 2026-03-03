package androidsmsgateway_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jszwec/csvutil"
	"github.com/therootcompany/golib/http/androidsmsgateway"
)

// csvLines marshals v as CSV and returns the header line and first data line.
func csvLines[T any](t *testing.T, v T) (header, row string) {
	t.Helper()
	b, err := csvutil.Marshal([]T{v})
	if err != nil {
		t.Fatalf("csvutil.Marshal: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 CSV lines, got %d:\n%s", len(lines), b)
	}
	return lines[0], lines[1]
}

// csvParseOne unmarshals a header+row CSV pair into T.
func csvParseOne[T any](t *testing.T, header, row string) T {
	t.Helper()
	var out []T
	if err := csvutil.Unmarshal([]byte(header+"\n"+row+"\n"), &out); err != nil {
		t.Fatalf("csvutil.Unmarshal: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("csvutil.Unmarshal: no rows returned")
	}
	return out[0]
}

func TestCSV_WebhookReceived(t *testing.T) {
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

	const (
		wantHeader = "deviceId,event,id,message,messageId,phoneNumber,receivedAt,simNumber,webhookId"
		wantRow    = "ffffffffceb0b1db0000018e937c815b,sms:received,Ey6ECgOkVVFjz3CL48B8C,Android is always a sweet treat!,abc123,+16505551212,2024-06-22T15:46:11+07:00,1,LreFUt-Z3sSq0JufY9uWB"
	)

	header, row := csvLines(t, *got)
	if header != wantHeader {
		t.Errorf("header:\n got  %q\n want %q", header, wantHeader)
	}
	if row != wantRow {
		t.Errorf("row:\n got  %q\n want %q", row, wantRow)
	}

	// Round-trip: parse the known CSV and verify fields.
	parsed := csvParseOne[androidsmsgateway.WebhookReceived](t, wantHeader, wantRow)
	if parsed.DeviceID != got.DeviceID {
		t.Errorf("DeviceID: got %q, want %q", parsed.DeviceID, got.DeviceID)
	}
	if parsed.Payload.Message != got.Payload.Message {
		t.Errorf("Message: got %q, want %q", parsed.Payload.Message, got.Payload.Message)
	}
	if parsed.Payload.MessageID != got.Payload.MessageID {
		t.Errorf("MessageID: got %q, want %q", parsed.Payload.MessageID, got.Payload.MessageID)
	}
	if parsed.Payload.PhoneNumber != got.Payload.PhoneNumber {
		t.Errorf("PhoneNumber: got %q, want %q", parsed.Payload.PhoneNumber, got.Payload.PhoneNumber)
	}
	if parsed.Payload.SimNumber != got.Payload.SimNumber {
		t.Errorf("SimNumber: got %d, want %d", parsed.Payload.SimNumber, got.Payload.SimNumber)
	}
	if !parsed.Payload.ReceivedAt.Equal(got.Payload.ReceivedAt) {
		t.Errorf("ReceivedAt: got %v, want %v", parsed.Payload.ReceivedAt, got.Payload.ReceivedAt)
	}
}

func TestCSV_WebhookSent(t *testing.T) {
	raw := []byte(`{
		"deviceId": "ffffffffceb0b1db0000018e937c815b",
		"event": "sms:sent",
		"id": "Ey6ECgOkVVFjz3CL48B8C",
		"payload": {
			"messageId": "msg-456",
			"sender": "+1234567890",
			"recipient": "+9998887777",
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

	const (
		wantHeader = "deviceId,event,id,messageId,partsCount,recipient,sender,simNumber,sentAt,webhookId"
		wantRow    = "ffffffffceb0b1db0000018e937c815b,sms:sent,Ey6ECgOkVVFjz3CL48B8C,msg-456,1,+9998887777,+1234567890,1,2026-02-18T02:05:00+07:00,LreFUt-Z3sSq0JufY9uWB"
	)

	header, row := csvLines(t, *got)
	if header != wantHeader {
		t.Errorf("header:\n got  %q\n want %q", header, wantHeader)
	}
	if row != wantRow {
		t.Errorf("row:\n got  %q\n want %q", row, wantRow)
	}

	// Round-trip.
	parsed := csvParseOne[androidsmsgateway.WebhookSent](t, wantHeader, wantRow)
	if parsed.Payload.MessageID != got.Payload.MessageID {
		t.Errorf("MessageID: got %q, want %q", parsed.Payload.MessageID, got.Payload.MessageID)
	}
	if parsed.Payload.Sender != got.Payload.Sender {
		t.Errorf("Sender: got %q, want %q", parsed.Payload.Sender, got.Payload.Sender)
	}
	if parsed.Payload.Recipient != got.Payload.Recipient {
		t.Errorf("Recipient: got %q, want %q", parsed.Payload.Recipient, got.Payload.Recipient)
	}
	if parsed.Payload.PartsCount != got.Payload.PartsCount {
		t.Errorf("PartsCount: got %d, want %d", parsed.Payload.PartsCount, got.Payload.PartsCount)
	}
	if !parsed.Payload.SentAt.Equal(got.Payload.SentAt) {
		t.Errorf("SentAt: got %v, want %v", parsed.Payload.SentAt, got.Payload.SentAt)
	}
}

func TestCSV_WebhookDelivered(t *testing.T) {
	raw := []byte(`{
		"deviceId": "ffffffffceb0b1db0000018e937c815b",
		"event": "sms:delivered",
		"id": "Ey6ECgOkVVFjz3CL48B8C",
		"payload": {
			"messageId": "msg-789",
			"sender": "+1234567890",
			"recipient": "+9998887777",
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

	const (
		wantHeader = "deviceId,event,id,deliveredAt,messageId,recipient,sender,simNumber,webhookId"
		wantRow    = "ffffffffceb0b1db0000018e937c815b,sms:delivered,Ey6ECgOkVVFjz3CL48B8C,2026-02-18T02:10:00+07:00,msg-789,+9998887777,+1234567890,1,LreFUt-Z3sSq0JufY9uWB"
	)

	header, row := csvLines(t, *got)
	if header != wantHeader {
		t.Errorf("header:\n got  %q\n want %q", header, wantHeader)
	}
	if row != wantRow {
		t.Errorf("row:\n got  %q\n want %q", row, wantRow)
	}

	// Round-trip.
	parsed := csvParseOne[androidsmsgateway.WebhookDelivered](t, wantHeader, wantRow)
	if parsed.Payload.MessageID != got.Payload.MessageID {
		t.Errorf("MessageID: got %q, want %q", parsed.Payload.MessageID, got.Payload.MessageID)
	}
	if parsed.Payload.Sender != got.Payload.Sender {
		t.Errorf("Sender: got %q, want %q", parsed.Payload.Sender, got.Payload.Sender)
	}
	if parsed.Payload.Recipient != got.Payload.Recipient {
		t.Errorf("Recipient: got %q, want %q", parsed.Payload.Recipient, got.Payload.Recipient)
	}
	if !parsed.Payload.DeliveredAt.Equal(got.Payload.DeliveredAt) {
		t.Errorf("DeliveredAt: got %v, want %v", parsed.Payload.DeliveredAt, got.Payload.DeliveredAt)
	}
}

func TestCSV_WebhookFailed(t *testing.T) {
	raw := []byte(`{
		"deviceId": "ffffffffceb0b1db0000018e937c815b",
		"event": "sms:failed",
		"id": "Ey6ECgOkVVFjz3CL48B8C",
		"payload": {
			"messageId": "msg-000",
			"sender": "+1234567890",
			"recipient": "+4445556666",
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

	const (
		wantHeader = "deviceId,event,id,failedAt,messageId,reason,recipient,sender,simNumber,webhookId"
		wantRow    = "ffffffffceb0b1db0000018e937c815b,sms:failed,Ey6ECgOkVVFjz3CL48B8C,2026-02-18T02:15:00+07:00,msg-000,Network error,+4445556666,+1234567890,3,LreFUt-Z3sSq0JufY9uWB"
	)

	header, row := csvLines(t, *got)
	if header != wantHeader {
		t.Errorf("header:\n got  %q\n want %q", header, wantHeader)
	}
	if row != wantRow {
		t.Errorf("row:\n got  %q\n want %q", row, wantRow)
	}

	// Round-trip.
	parsed := csvParseOne[androidsmsgateway.WebhookFailed](t, wantHeader, wantRow)
	if parsed.Payload.MessageID != got.Payload.MessageID {
		t.Errorf("MessageID: got %q, want %q", parsed.Payload.MessageID, got.Payload.MessageID)
	}
	if parsed.Payload.Reason != got.Payload.Reason {
		t.Errorf("Reason: got %q, want %q", parsed.Payload.Reason, got.Payload.Reason)
	}
	if parsed.Payload.SimNumber != got.Payload.SimNumber {
		t.Errorf("SimNumber: got %d, want %d", parsed.Payload.SimNumber, got.Payload.SimNumber)
	}
	if !parsed.Payload.FailedAt.Equal(got.Payload.FailedAt) {
		t.Errorf("FailedAt: got %v, want %v", parsed.Payload.FailedAt, got.Payload.FailedAt)
	}
}

func TestCSV_WebhookPing(t *testing.T) {
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
	// PingedAt is set by the server from X-Timestamp; use a fixed value here.
	got.PingedAt = time.Date(2026, 2, 23, 0, 1, 1, 0, time.UTC)

	const (
		wantHeader = "deviceId,event,id,battery_charging,battery_level,connection_cellular,connection_status,connection_transport,messages_failed,releaseId,status,version,webhookId,pingedAt"
		wantRow    = "ffffffffceb0b1db00000192672f2204,system:ping,mjDoocQLCsOIDra_GthuI,4,94,0,TRUE,4,0,1,pass,1.0.0,LreFUt-Z3sSq0JufY9uWB,2026-02-23T00:01:01Z"
	)

	header, row := csvLines(t, *got)
	if header != wantHeader {
		t.Errorf("header:\n got  %q\n want %q", header, wantHeader)
	}
	if row != wantRow {
		t.Errorf("row:\n got  %q\n want %q", row, wantRow)
	}

	// Round-trip: parse the known CSV and verify key fields.
	// (BoolHealthCheck and HealthCheck are write-only in CSV — their text form is
	// a single number, so parsing back gives only ObservedValue; that is enough to
	// verify the round-trip.)
	parsed := csvParseOne[androidsmsgateway.WebhookPing](t, wantHeader, wantRow)
	if parsed.DeviceID != got.DeviceID {
		t.Errorf("DeviceID: got %q, want %q", parsed.DeviceID, got.DeviceID)
	}
	if parsed.Payload.Health.Status != got.Payload.Health.Status {
		t.Errorf("Health.Status: got %q, want %q", parsed.Payload.Health.Status, got.Payload.Health.Status)
	}
	if parsed.Payload.Health.Version != got.Payload.Health.Version {
		t.Errorf("Health.Version: got %q, want %q", parsed.Payload.Health.Version, got.Payload.Health.Version)
	}
	if parsed.Payload.Health.ReleaseID != got.Payload.Health.ReleaseID {
		t.Errorf("Health.ReleaseID: got %d, want %d", parsed.Payload.Health.ReleaseID, got.Payload.Health.ReleaseID)
	}
	if !parsed.PingedAt.Equal(got.PingedAt) {
		t.Errorf("PingedAt: got %v, want %v", parsed.PingedAt, got.PingedAt)
	}
}
