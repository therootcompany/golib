package androidsmsgateway

import (
	"encoding/json"
	"errors"
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
	DeviceID   string             `json:"deviceId"`
	Event      string             `json:"event"`
	ID         string             `json:"id"`
	Payload    WebhookSentPayload `json:"payload"`
	WebhookID  string             `json:"webhookId"`
	XSignature string             `json:"x-signature"`
	XTimestamp int64              `json:"x-timestamp"`
}

// GetEvent marks WebhookSent as part of the WebhookEvent interface.
func (w *WebhookSent) GetEvent() string {
	return w.Event
}

// WebhookSentPayload contains details about the sent SMS.
type WebhookSentPayload struct {
	MessageID   string    `json:"messageId"`
	PartsCount  int       `json:"partsCount"`
	PhoneNumber string    `json:"phoneNumber"`
	SentAt      time.Time `json:"sentAt"`
}

// WebhookDelivered represents a webhook notification for an SMS delivered event.
type WebhookDelivered struct {
	DeviceID   string                  `json:"deviceId"`
	Event      string                  `json:"event"`
	ID         string                  `json:"id"`
	Payload    WebhookDeliveredPayload `json:"payload"`
	WebhookID  string                  `json:"webhookId"`
	XSignature string                  `json:"x-signature"`
	XTimestamp int64                   `json:"x-timestamp"`
}

// GetEvent marks WebhookDelivered as part of the WebhookEvent interface.
func (w *WebhookDelivered) GetEvent() string {
	return w.Event
}

// WebhookDeliveredPayload contains details about the delivered SMS.
type WebhookDeliveredPayload struct {
	DeliveredAt time.Time `json:"deliveredAt"`
	MessageID   string    `json:"messageId"`
	PhoneNumber string    `json:"phoneNumber"`
}

// WebhookReceived represents a webhook notification for an SMS received event.
type WebhookReceived struct {
	DeviceID   string                 `json:"deviceId"`
	Event      string                 `json:"event"`
	ID         string                 `json:"id"`
	Payload    WebhookReceivedPayload `json:"payload"`
	WebhookID  string                 `json:"webhookId"`
	XSignature string                 `json:"x-signature"`
	XTimestamp int64                  `json:"x-timestamp"`
}

// GetEvent marks WebhookDelivered as part of the WebhookEvent interface.
func (w *WebhookReceived) GetEvent() string {
	return w.Event
}

// WebhookReceivedPayload contains details about the received SMS.
type WebhookReceivedPayload struct {
	Message     string    `json:"message"`
	MessageID   string    `json:"messageId"`
	PhoneNumber string    `json:"phoneNumber"`
	ReceivedAt  time.Time `json:"receivedAt"`
	SimNumber   int       `json:"simNumber"`
}

// WebhookPing represents a system:ping webhook event.
type WebhookPing struct {
	DeviceID   string             `json:"deviceId"`
	Event      string             `json:"event"`
	ID         string             `json:"id"`
	Payload    WebhookPingPayload `json:"payload"`
	WebhookID  string             `json:"webhookId"`
	XSignature string             `json:"x-signature"`
	XTimestamp int64              `json:"x-timestamp"`
}

// GetEvent marks WebhookPing as part of the WebhookEvent interface.
func (w *WebhookPing) GetEvent() string {
	return w.Event
}

// WebhookPingPayload contains the health data reported by a system:ping event.
type WebhookPingPayload struct {
	Health DeviceHealth `json:"health"`
}

// DeviceHealth is the top-level health object inside a system:ping payload.
type DeviceHealth struct {
	Checks    map[string]HealthCheck `json:"checks"`
	ReleaseID int                    `json:"releaseId"`
	Status    string                 `json:"status"`
	Version   string                 `json:"version"`
}

// HealthCheck represents a single named health check result.
type HealthCheck struct {
	Description   string  `json:"description"`
	ObservedUnit  string  `json:"observedUnit"`
	ObservedValue float64 `json:"observedValue"`
	Status        string  `json:"status"`
}

// Decode decodes the raw Payload based on the Event field and returns the appropriate WebhookEvent.
func Decode(webhook *Webhook) (WebhookEvent, error) {
	switch webhook.Event {
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
