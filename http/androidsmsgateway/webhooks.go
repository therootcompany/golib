package androidsmsgateway

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// WebhookEvent is an interface for all webhook event types.
type WebhookEvent interface {
	GetEvent() string
}

// Webhook represents a webhook notification for an SMS sent event.
type Webhook struct {
	DeviceID   string          `json:"deviceId"`
	Event      string          `json:"event"`
	ID         string          `json:"id"`
	Payload    json.RawMessage `json:"payload"`
	WebhookID  string          `json:"webhookId"`
	XSignature string          `json:"x-signature"`
	XTimestamp int64           `json:"x-timestamp"`
}

// WebhookSent represents a webhook notification for an SMS sent event.
type WebhookSent struct {
	DeviceID   string             `json:"deviceId"    csv:"deviceId"`
	Event      string             `json:"event"       csv:"event"`
	ID         string             `json:"id"          csv:"id"`
	Payload    WebhookSentPayload `json:"payload"     csv:",inline"`
	WebhookID  string             `json:"webhookId"   csv:"webhookId"`
	XSignature string             `json:"x-signature" csv:"-"`
	XTimestamp int64              `json:"x-timestamp" csv:"-"`
}

// GetEvent marks WebhookSent as part of the WebhookEvent interface.
func (w *WebhookSent) GetEvent() string {
	return w.Event
}

// WebhookSentPayload contains details about the sent SMS.
type WebhookSentPayload struct {
	MessageID  string    `json:"messageId"  csv:"messageId"`
	PartsCount int       `json:"partsCount" csv:"partsCount"`
	Recipient  string    `json:"recipient"  csv:"recipient"`
	Sender     string    `json:"sender"     csv:"sender"`
	SimNumber  int       `json:"simNumber"  csv:"simNumber"`
	SentAt     time.Time `json:"sentAt"     csv:"sentAt"`
}

// WebhookDelivered represents a webhook notification for an SMS delivered event.
type WebhookDelivered struct {
	DeviceID   string                  `json:"deviceId"    csv:"deviceId"`
	Event      string                  `json:"event"       csv:"event"`
	ID         string                  `json:"id"          csv:"id"`
	Payload    WebhookDeliveredPayload `json:"payload"     csv:",inline"`
	WebhookID  string                  `json:"webhookId"   csv:"webhookId"`
	XSignature string                  `json:"x-signature" csv:"-"`
	XTimestamp int64                   `json:"x-timestamp" csv:"-"`
}

// GetEvent marks WebhookDelivered as part of the WebhookEvent interface.
func (w *WebhookDelivered) GetEvent() string {
	return w.Event
}

// WebhookDeliveredPayload contains details about the delivered SMS.
type WebhookDeliveredPayload struct {
	DeliveredAt time.Time `json:"deliveredAt" csv:"deliveredAt"`
	MessageID   string    `json:"messageId"   csv:"messageId"`
	Recipient   string    `json:"recipient"   csv:"recipient"`
	Sender      string    `json:"sender"      csv:"sender"`
	SimNumber   int       `json:"simNumber"   csv:"simNumber"`
}

// WebhookReceived represents a webhook notification for an SMS received event.
type WebhookReceived struct {
	DeviceID   string                 `json:"deviceId"    csv:"deviceId"`
	Event      string                 `json:"event"       csv:"event"`
	ID         string                 `json:"id"          csv:"id"`
	Payload    WebhookReceivedPayload `json:"payload"     csv:",inline"`
	WebhookID  string                 `json:"webhookId"   csv:"webhookId"`
	XSignature string                 `json:"x-signature" csv:"-"`
	XTimestamp int64                  `json:"x-timestamp" csv:"-"`
}

// GetEvent marks WebhookDelivered as part of the WebhookEvent interface.
func (w *WebhookReceived) GetEvent() string {
	return w.Event
}

// WebhookReceivedPayload contains details about the received SMS.
type WebhookReceivedPayload struct {
	Message     string    `json:"message"     csv:"message"`
	MessageID   string    `json:"messageId"   csv:"messageId"`
	PhoneNumber string    `json:"phoneNumber" csv:"phoneNumber"`
	ReceivedAt  time.Time `json:"receivedAt"  csv:"receivedAt"`
	SimNumber   int       `json:"simNumber"   csv:"simNumber"`
}

// WebhookDataReceived represents a webhook notification for an sms:data-received event.
type WebhookDataReceived struct {
	DeviceID   string                     `json:"deviceId"    csv:"deviceId"`
	Event      string                     `json:"event"       csv:"event"`
	ID         string                     `json:"id"          csv:"id"`
	Payload    WebhookDataReceivedPayload `json:"payload"     csv:",inline"`
	WebhookID  string                     `json:"webhookId"   csv:"webhookId"`
	XSignature string                     `json:"x-signature" csv:"-"`
	XTimestamp int64                      `json:"x-timestamp" csv:"-"`
}

// GetEvent marks WebhookDataReceived as part of the WebhookEvent interface.
func (w *WebhookDataReceived) GetEvent() string {
	return w.Event
}

// WebhookDataReceivedPayload contains details about the received binary SMS.
type WebhookDataReceivedPayload struct {
	Data       string    `json:"data"       csv:"data"`
	MessageID  string    `json:"messageId"  csv:"messageId"`
	ReceivedAt time.Time `json:"receivedAt" csv:"receivedAt"`
	Recipient  string    `json:"recipient"  csv:"recipient"`
	Sender     string    `json:"sender"     csv:"sender"`
	SimNumber  int       `json:"simNumber"  csv:"simNumber"`
}

// WebhookMMSReceived represents a webhook notification for an mms:received event.
type WebhookMMSReceived struct {
	DeviceID   string                    `json:"deviceId"    csv:"deviceId"`
	Event      string                    `json:"event"       csv:"event"`
	ID         string                    `json:"id"          csv:"id"`
	Payload    WebhookMMSReceivedPayload `json:"payload"     csv:",inline"`
	WebhookID  string                    `json:"webhookId"   csv:"webhookId"`
	XSignature string                    `json:"x-signature" csv:"-"`
	XTimestamp int64                     `json:"x-timestamp" csv:"-"`
}

// GetEvent marks WebhookMMSReceived as part of the WebhookEvent interface.
func (w *WebhookMMSReceived) GetEvent() string {
	return w.Event
}

// WebhookMMSReceivedPayload contains details about the received MMS.
type WebhookMMSReceivedPayload struct {
	ContentClass  string    `json:"contentClass"  csv:"contentClass"`
	MessageID     string    `json:"messageId"     csv:"messageId"`
	ReceivedAt    time.Time `json:"receivedAt"    csv:"receivedAt"`
	Recipient     string    `json:"recipient"     csv:"recipient"`
	Sender        string    `json:"sender"        csv:"sender"`
	SimNumber     int       `json:"simNumber"     csv:"simNumber"`
	Size          int       `json:"size"          csv:"size"`
	Subject       string    `json:"subject"       csv:"subject"`
	TransactionID string    `json:"transactionId" csv:"transactionId"`
}

// WebhookFailed represents a webhook notification for an sms:failed event.
type WebhookFailed struct {
	DeviceID   string               `json:"deviceId"    csv:"deviceId"`
	Event      string               `json:"event"       csv:"event"`
	ID         string               `json:"id"          csv:"id"`
	Payload    WebhookFailedPayload `json:"payload"     csv:",inline"`
	WebhookID  string               `json:"webhookId"   csv:"webhookId"`
	XSignature string               `json:"x-signature" csv:"-"`
	XTimestamp int64                `json:"x-timestamp" csv:"-"`
}

// GetEvent marks WebhookFailed as part of the WebhookEvent interface.
func (w *WebhookFailed) GetEvent() string {
	return w.Event
}

// WebhookFailedPayload contains details about the failed SMS.
type WebhookFailedPayload struct {
	FailedAt  time.Time `json:"failedAt"   csv:"failedAt"`
	MessageID string    `json:"messageId"  csv:"messageId"`
	Reason    string    `json:"reason"     csv:"reason"`
	Recipient string    `json:"recipient"  csv:"recipient"`
	Sender    string    `json:"sender"     csv:"sender"`
	SimNumber int       `json:"simNumber"  csv:"simNumber"`
}

// WebhookPing represents a system:ping webhook event.
type WebhookPing struct {
	DeviceID   string             `json:"deviceId"           csv:"deviceId"`
	Event      string             `json:"event"              csv:"event"`
	ID         string             `json:"id"                 csv:"id"`
	Payload    WebhookPingPayload `json:"payload"            csv:",inline"`
	WebhookID  string             `json:"webhookId"          csv:"webhookId"`
	PingedAt   time.Time          `json:"pingedAt,omitempty" csv:"pingedAt"`
	XSignature string             `json:"x-signature"        csv:"-"`
	XTimestamp int64              `json:"x-timestamp"        csv:"-"`
}

// GetEvent marks WebhookPing as part of the WebhookEvent interface.
func (w *WebhookPing) GetEvent() string {
	return w.Event
}

// WebhookPingPayload contains the health data reported by a system:ping event.
type WebhookPingPayload struct {
	Health DeviceHealth `json:"health" csv:",inline"`
}

// DeviceHealth is the top-level health object inside a system:ping payload.
// Named fields use colon json tags matching the API key names inside "checks".
type DeviceHealth struct {
	Checks    DeviceChecks `json:"checks"    csv:",inline"`
	ReleaseID int          `json:"releaseId" csv:"releaseId"`
	Status    string       `json:"status"    csv:"status"`
	Version   string       `json:"version"   csv:"version"`
}

// DeviceChecks holds the individual health checks reported by the device.
// Go field names are camelCase; json tags carry the colon-delimited API key names.
// csv tags mirror the documentation key names with underscores instead of colons.
type DeviceChecks struct {
	BatteryCharging     HealthCheck     `json:"battery:charging"     csv:"battery_charging"`
	BatteryLevel        HealthCheck     `json:"battery:level"        csv:"battery_level"`
	ConnectionCellular  HealthCheck     `json:"connection:cellular"  csv:"connection_cellular"`
	ConnectionStatus    BoolHealthCheck `json:"connection:status"    csv:"connection_status"`
	ConnectionTransport HealthCheck     `json:"connection:transport" csv:"connection_transport"`
	MessagesFailed      HealthCheck     `json:"messages:failed"      csv:"messages_failed"`
}

// HealthCheck represents a single named health check result.
// MarshalText returns the observed value as a number for CSV encoding.
// MarshalJSON overrides MarshalText so JSON output is always the full object.
type HealthCheck struct {
	Description   string  `json:"description"`
	ObservedUnit  string  `json:"observedUnit"`
	ObservedValue float64 `json:"observedValue"`
	Status        string  `json:"status"`
}

// MarshalText implements encoding.TextMarshaler for CSV serialisation.
// Returns the observed numeric value so each check becomes a single CSV column.
func (c HealthCheck) MarshalText() ([]byte, error) {
	return []byte(strconv.FormatFloat(c.ObservedValue, 'f', -1, 64)), nil
}

// MarshalJSON prevents MarshalText from being used during JSON serialisation,
// ensuring HealthCheck is always encoded as a full JSON object.
func (c HealthCheck) MarshalJSON() ([]byte, error) {
	type alias HealthCheck
	return json.Marshal(alias(c))
}

// UnmarshalText implements encoding.TextUnmarshaler for CSV deserialisation.
// Parses the numeric observed value produced by MarshalText.
func (c *HealthCheck) UnmarshalText(b []byte) error {
	v, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return err
	}
	c.ObservedValue = v
	return nil
}

// UnmarshalJSON prevents UnmarshalText from being used during JSON deserialisation,
// ensuring HealthCheck is always decoded as a full JSON object.
func (c *HealthCheck) UnmarshalJSON(b []byte) error {
	type alias HealthCheck
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*c = HealthCheck(a)
	return nil
}

// BoolHealthCheck is a HealthCheck whose CSV representation is TRUE or FALSE
// based on whether ObservedValue is non-zero.  Used for connection:status.
type BoolHealthCheck HealthCheck

// MarshalText implements encoding.TextMarshaler for CSV serialisation.
func (c BoolHealthCheck) MarshalText() ([]byte, error) {
	if c.ObservedValue != 0 {
		return []byte("TRUE"), nil
	}
	return []byte("FALSE"), nil
}

// MarshalJSON prevents MarshalText from being used during JSON serialisation,
// ensuring BoolHealthCheck is always encoded as a full JSON object.
func (c BoolHealthCheck) MarshalJSON() ([]byte, error) {
	type alias BoolHealthCheck
	return json.Marshal(alias(c))
}

// UnmarshalText implements encoding.TextUnmarshaler for CSV deserialisation.
// Parses "TRUE" (→ 1) or "FALSE" (→ 0) back into ObservedValue.
func (c *BoolHealthCheck) UnmarshalText(b []byte) error {
	switch string(b) {
	case "TRUE":
		c.ObservedValue = 1
	case "FALSE":
		c.ObservedValue = 0
	default:
		v, err := strconv.ParseFloat(string(b), 64)
		if err != nil {
			return err
		}
		c.ObservedValue = v
	}
	return nil
}

// UnmarshalJSON prevents UnmarshalText from being used during JSON deserialisation,
// ensuring BoolHealthCheck is always decoded as a full JSON object.
func (c *BoolHealthCheck) UnmarshalJSON(b []byte) error {
	type alias BoolHealthCheck
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*c = BoolHealthCheck(a)
	return nil
}

// Decode decodes the raw Payload based on the Event field and returns the appropriate WebhookEvent.
func Decode(webhook *Webhook) (WebhookEvent, error) {
	switch webhook.Event {
	case "system:ping":
		var ping WebhookPing
		ping.DeviceID = webhook.DeviceID
		ping.Event = webhook.Event
		ping.ID = webhook.ID
		ping.WebhookID = webhook.WebhookID
		ping.XSignature = webhook.XSignature
		ping.XTimestamp = webhook.XTimestamp
		if err := json.Unmarshal(webhook.Payload, &ping.Payload); err != nil {
			return nil, errors.New("failed to decode system:ping payload: " + err.Error())
		}
		return &ping, nil
	case "sms:sent":
		var sent WebhookSent
		sent.DeviceID = webhook.DeviceID
		sent.Event = webhook.Event
		sent.ID = webhook.ID
		sent.WebhookID = webhook.WebhookID
		sent.XSignature = webhook.XSignature
		sent.XTimestamp = webhook.XTimestamp
		if err := json.Unmarshal(webhook.Payload, &sent.Payload); err != nil {
			return nil, errors.New("failed to decode sms:sent payload: " + err.Error())
		}
		return &sent, nil
	case "sms:delivered":
		var delivered WebhookDelivered
		delivered.DeviceID = webhook.DeviceID
		delivered.Event = webhook.Event
		delivered.ID = webhook.ID
		delivered.WebhookID = webhook.WebhookID
		delivered.XSignature = webhook.XSignature
		delivered.XTimestamp = webhook.XTimestamp
		if err := json.Unmarshal(webhook.Payload, &delivered.Payload); err != nil {
			return nil, errors.New("failed to decode sms:delivered payload: " + err.Error())
		}
		return &delivered, nil
	case "sms:data-received":
		var ev WebhookDataReceived
		ev.DeviceID = webhook.DeviceID
		ev.Event = webhook.Event
		ev.ID = webhook.ID
		ev.WebhookID = webhook.WebhookID
		ev.XSignature = webhook.XSignature
		ev.XTimestamp = webhook.XTimestamp
		if err := json.Unmarshal(webhook.Payload, &ev.Payload); err != nil {
			return nil, errors.New("failed to decode sms:data-received payload: " + err.Error())
		}
		return &ev, nil
	case "mms:received":
		var ev WebhookMMSReceived
		ev.DeviceID = webhook.DeviceID
		ev.Event = webhook.Event
		ev.ID = webhook.ID
		ev.WebhookID = webhook.WebhookID
		ev.XSignature = webhook.XSignature
		ev.XTimestamp = webhook.XTimestamp
		if err := json.Unmarshal(webhook.Payload, &ev.Payload); err != nil {
			return nil, errors.New("failed to decode mms:received payload: " + err.Error())
		}
		return &ev, nil
	case "sms:failed":
		var ev WebhookFailed
		ev.DeviceID = webhook.DeviceID
		ev.Event = webhook.Event
		ev.ID = webhook.ID
		ev.WebhookID = webhook.WebhookID
		ev.XSignature = webhook.XSignature
		ev.XTimestamp = webhook.XTimestamp
		if err := json.Unmarshal(webhook.Payload, &ev.Payload); err != nil {
			return nil, errors.New("failed to decode sms:failed payload: " + err.Error())
		}
		return &ev, nil
	case "sms:received":
		var received WebhookReceived
		received.DeviceID = webhook.DeviceID
		received.Event = webhook.Event
		received.ID = webhook.ID
		received.WebhookID = webhook.WebhookID
		received.XSignature = webhook.XSignature
		received.XTimestamp = webhook.XTimestamp
		if err := json.Unmarshal(webhook.Payload, &received.Payload); err != nil {
			return nil, errors.New("failed to decode sms:received payload: " + err.Error())
		}
		return &received, nil
	default:
		return nil, errors.New("unknown event type: " + webhook.Event)
	}
}
