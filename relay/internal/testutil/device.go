// Package testutil provides a simulated Android device that speaks the real handshake. Test use only.
package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/coder/websocket"
)

type Device struct {
	Key  *ecdsa.PrivateKey
	SPKI []byte
	ID   string
}

func NewDevice(t testing.TB) *Device {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	return &Device{Key: k, SPKI: spki, ID: hex.EncodeToString(sum[:])}
}

func (d *Device) PublicKeyB64() string { return base64.StdEncoding.EncodeToString(d.SPKI) }

func (d *Device) Sign(msg []byte) []byte {
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, d.Key, h[:])
	if err != nil {
		panic(err)
	}
	return sig
}

// Env builds a valid envelope from this device.
func (d *Device) Env(typ protocol.MessageType, corr string, payload any) *protocol.Envelope {
	b, _ := json.Marshal(payload)
	now := time.Now().UTC()
	exp := now.Add(30 * time.Second)
	e := &protocol.Envelope{V: 1, Type: typ, ID: protocol.NewID(), Corr: corr, Device: d.ID, Payload: b}
	if typ == protocol.TypeCommand || typ == protocol.TypeCancel {
		e.TS, e.Exp = &now, &exp
	}
	return e
}

func Send(ctx context.Context, c *websocket.Conn, e *protocol.Envelope) error {
	b, err := e.Marshal()
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, b)
}

func Recv(ctx context.Context, c *websocket.Conn) (*protocol.Envelope, error) {
	_, data, err := c.Read(ctx)
	if err != nil {
		return nil, err
	}
	return protocol.Parse(data)
}

// WSURL turns an http(s) test-server URL into the device endpoint URL.
func WSURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http") + "/v1/device/ws"
}

// SignFunc produces the auth signature from the relay's nonce.
type SignFunc func(nonce []byte) []byte

// Handshake performs hello -> hello_ack -> auth and returns the nonce the relay issued.
// sign decides what is signed, so tests can send bad signatures.
func (d *Device) Handshake(ctx context.Context, c *websocket.Conn, sign SignFunc) ([]byte, error) {
	if err := Send(ctx, c, d.Env(protocol.TypeHello, "", protocol.HelloPayload{Versions: []int{1}, AppVersion: "test"})); err != nil {
		return nil, err
	}
	ack, err := Recv(ctx, c)
	if err != nil {
		return nil, err
	}
	var ap protocol.HelloAckPayload
	if err := json.Unmarshal(ack.Payload, &ap); err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(ap.Nonce)
	if err != nil {
		return nil, err
	}
	sig := sign(nonce)
	return nonce, Send(ctx, c, d.Env(protocol.TypeAuth, "", protocol.AuthPayload{Signature: base64.StdEncoding.EncodeToString(sig)}))
}

// ProperSign signs the correct message for origin.
func (d *Device) ProperSign(origin string) SignFunc {
	return func(nonce []byte) []byte { return d.Sign(protocol.AuthMessage(nonce, d.ID, origin)) }
}

// Connect dials and authenticates correctly.
func (d *Device) Connect(ctx context.Context, t testing.TB, httpURL, origin string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(ctx, WSURL(httpURL), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Handshake(ctx, c, d.ProperSign(origin)); err != nil {
		t.Fatal(err)
	}
	// A heartbeat round trip proves the relay accepted us (the relay answers heartbeats only after auth).
	if err := Send(ctx, c, d.Env(protocol.TypeHeartbeat, "", struct{}{})); err != nil {
		t.Fatal(err)
	}
	if e, err := Recv(ctx, c); err != nil || e.Type != protocol.TypeHeartbeat {
		t.Fatalf("not authenticated: %v %v", e, err)
	}
	t.Cleanup(func() { c.CloseNow() })
	return c
}
