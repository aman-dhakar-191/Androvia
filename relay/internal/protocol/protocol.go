// Package protocol implements the Androvia message envelope (docs/protocol/envelope.md).
// Parsing is strict and mirrors the Android implementation in android/core: unknown fields,
// wrong types and oversize input are rejected, never ignored.
package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"
)

const (
	Version         = 1
	MaxMessageBytes = 65536
	MaxLifetime     = 60 * time.Second
	MaxClockSkew    = 30 * time.Second
)

type MessageType string

const (
	TypeHello     MessageType = "hello"
	TypeHelloAck  MessageType = "hello_ack"
	TypeAuth      MessageType = "auth" // device -> relay only; completes the handshake
	TypeHeartbeat MessageType = "heartbeat"
	TypeCommand   MessageType = "command"
	TypeResult    MessageType = "result"
	TypeError     MessageType = "error"
	TypeCancel    MessageType = "cancel"
)

var knownTypes = map[MessageType]bool{
	TypeHello: true, TypeHelloAck: true, TypeAuth: true, TypeHeartbeat: true,
	TypeCommand: true, TypeResult: true, TypeError: true, TypeCancel: true,
}

// Code is a stable wire error code. Never rename a value.
type Code string

const (
	CodeMalformed          Code = "malformed"
	CodeUnsupportedVersion Code = "unsupported_version"
	CodeUnsupportedMessage Code = "unsupported_message"
	CodeTooLarge           Code = "too_large"
	CodeExpired            Code = "expired"
	CodeReplayed           Code = "replayed"
	CodePermissionDenied   Code = "permission_denied"
	CodeRateLimited        Code = "rate_limited"
	CodeInternal           Code = "internal"
)

// Error is a protocol violation. ID is set once the message id was parsed.
type Error struct {
	Code Code
	Msg  string
	ID   string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Msg) }

type Envelope struct {
	V       int             `json:"v"`
	Type    MessageType     `json:"type"`
	ID      string          `json:"id"`
	Corr    string          `json:"corr,omitempty"`
	Device  string          `json:"device"`
	TS      *time.Time      `json:"ts,omitempty"`
	Exp     *time.Time      `json:"exp,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

var (
	uuidRE   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	deviceRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidDeviceID reports whether s looks like a device id (hex SHA-256 of the public key).
func ValidDeviceID(s string) bool { return deviceRE.MatchString(s) }

// ValidID reports whether s is a UUID.
func ValidID(s string) bool { return uuidRE.MatchString(s) }

// wire mirrors Envelope with pointers so missing fields can be told from zero values.
type wire struct {
	V       *int            `json:"v"`
	Type    *string         `json:"type"`
	ID      *string         `json:"id"`
	Corr    *string         `json:"corr"`
	Device  *string         `json:"device"`
	TS      *string         `json:"ts"`
	Exp     *string         `json:"exp"`
	Payload json.RawMessage `json:"payload"`
}

// Parse validates raw and returns the envelope, or an *Error.
func Parse(raw []byte) (*Envelope, error) {
	if len(raw) > MaxMessageBytes {
		return nil, &Error{Code: CodeTooLarge, Msg: fmt.Sprintf("message exceeds %d bytes", MaxMessageBytes)}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	// Peek the id first so every later error can be correlated.
	var peek struct {
		ID *string `json:"id"`
	}
	var id string
	if err := json.Unmarshal(raw, &peek); err == nil && peek.ID != nil && uuidRE.MatchString(*peek.ID) {
		id = *peek.ID
	}
	fail := func(c Code, m string) (*Envelope, error) { return nil, &Error{Code: c, Msg: m, ID: id} }

	var w wire
	if err := dec.Decode(&w); err != nil {
		if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
			return fail(CodeMalformed, "invalid or unknown field")
		}
		return fail(CodeMalformed, "message must be a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return fail(CodeMalformed, "trailing data after message")
	}

	if w.ID == nil || !uuidRE.MatchString(*w.ID) {
		return fail(CodeMalformed, "id must be a UUID")
	}
	if w.V == nil {
		return fail(CodeMalformed, "v must be an integer")
	}
	if *w.V != Version {
		return fail(CodeUnsupportedVersion, "unsupported protocol version")
	}
	if w.Type == nil {
		return fail(CodeMalformed, "type must be a string")
	}
	t := MessageType(*w.Type)
	if !knownTypes[t] {
		return fail(CodeUnsupportedMessage, "unknown message type")
	}
	var corr string
	if w.Corr != nil {
		if !uuidRE.MatchString(*w.Corr) {
			return fail(CodeMalformed, "corr must be a UUID")
		}
		corr = *w.Corr
	}
	if t == TypeCommand && corr != "" {
		return fail(CodeMalformed, "command must not carry corr")
	}
	if (t == TypeResult || t == TypeError || t == TypeCancel) && corr == "" {
		return fail(CodeMalformed, "corr is required")
	}
	if w.Device == nil || !deviceRE.MatchString(*w.Device) {
		return fail(CodeMalformed, "device must be 64 lowercase hex characters")
	}
	timed := t == TypeCommand || t == TypeCancel
	ts, err := parseTime(w.TS, timed)
	if err != nil {
		return fail(CodeMalformed, "ts must be an ISO-8601 instant")
	}
	exp, err := parseTime(w.Exp, timed)
	if err != nil {
		return fail(CodeMalformed, "exp must be an ISO-8601 instant")
	}
	p := bytes.TrimSpace(w.Payload)
	if len(p) == 0 || p[0] != '{' {
		return fail(CodeMalformed, "payload must be an object")
	}
	return &Envelope{V: *w.V, Type: t, ID: *w.ID, Corr: corr, Device: *w.Device, TS: ts, Exp: exp, Payload: p}, nil
}

func parseTime(s *string, required bool) (*time.Time, error) {
	if s == nil {
		if required {
			return nil, fmt.Errorf("missing")
		}
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// CheckWindow validates ts/exp of a timed message against now.
func (e *Envelope) CheckWindow(now time.Time) error {
	if e.TS == nil || e.Exp == nil {
		return &Error{Code: CodeMalformed, Msg: "ts and exp required", ID: e.ID}
	}
	if !e.Exp.After(*e.TS) || e.Exp.Sub(*e.TS) > MaxLifetime {
		return &Error{Code: CodeMalformed, Msg: "invalid validity window", ID: e.ID}
	}
	if !e.Exp.After(now) || e.TS.After(now.Add(MaxClockSkew)) {
		return &Error{Code: CodeExpired, Msg: "message is expired or not yet valid", ID: e.ID}
	}
	return nil
}

// Marshal encodes the envelope.
func (e *Envelope) Marshal() ([]byte, error) {
	if len(e.Payload) == 0 {
		e.Payload = json.RawMessage(`{}`)
	}
	return json.Marshal(e)
}

// NewID returns a random (version 4) UUID.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Payloads.

type HelloPayload struct {
	Versions   []int  `json:"versions"`
	AppVersion string `json:"app_version,omitempty"`
}

type HelloAckPayload struct {
	Nonce   string `json:"nonce"` // base64 (std), 32 random bytes
	Version int    `json:"version"`
}

type AuthPayload struct {
	Signature string `json:"signature"` // base64 (std) ASN.1 DER ECDSA over AuthMessage
}

type CommandPayload struct {
	Capability string          `json:"capability"`
	Version    int             `json:"version"`
	Args       json.RawMessage `json:"args"`
}

type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// AuthPrefix domain-separates handshake signatures from any other use of the device key.
const AuthPrefix = "androvia/relay-auth/v1\x00"

// AuthMessage is what the device signs: prefix || nonce || deviceID || relayOrigin.
// nonce is fixed length (32) and deviceID fixed length (64), so the concatenation is unambiguous.
func AuthMessage(nonce []byte, deviceID, relayOrigin string) []byte {
	m := make([]byte, 0, len(AuthPrefix)+len(nonce)+len(deviceID)+len(relayOrigin))
	m = append(m, AuthPrefix...)
	m = append(m, nonce...)
	m = append(m, deviceID...)
	m = append(m, relayOrigin...)
	return m
}

// NewError builds an error envelope answering corr.
func NewError(deviceID, corr string, code Code, msg string, now time.Time) *Envelope {
	p, _ := json.Marshal(ErrorPayload{Code: string(code), Message: msg})
	if corr == "" {
		corr = NewID() // error messages must carry corr (receivers enforce it); there was no usable id to answer
	}
	return &Envelope{V: Version, Type: TypeError, ID: NewID(), Corr: corr, Device: deviceID, TS: &now, Payload: p}
}
