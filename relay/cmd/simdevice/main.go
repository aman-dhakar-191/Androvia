// Command simdevice is a simulated Androvia phone for demos and tests: it registers nothing and enables nothing by
// itself, it only speaks the device side of the relay protocol with its own key, and answers device.info.
//
//	simdevice -key phone.pem -print-registration          # prints the device id and the public key to register
//	simdevice -key phone.pem -relay wss://relay.example.com
//
// The private key (PEM, created on first use) never leaves the file. Do not use this against a relay you do not control.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/keys"
	"github.com/aman-dhakar-191/androvia/relay/internal/protocol"
	"github.com/coder/websocket"
)

func main() {
	keyPath := flag.String("key", "simdevice-key.pem", "private key file (created if missing)")
	relay := flag.String("relay", "", "relay public origin, exactly RELAY_PUBLIC_ORIGIN (wss://host[:port])")
	insecure := flag.Bool("allow-insecure", false, "allow ws:// (development only)")
	model := flag.String("model", "Simulated Phone", "model name to report")
	print := flag.Bool("print-registration", false, "print the device id and public key, then exit")
	flag.Parse()

	priv, err := loadOrCreate(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	id := keys.ID(spki)
	if *print {
		fmt.Printf("device_id=%s\npublic_key=%s\n", id, base64.StdEncoding.EncodeToString(spki))
		return
	}
	origin := strings.ToLower(strings.TrimRight(*relay, "/"))
	if !strings.HasPrefix(origin, "wss://") && !(*insecure && strings.HasPrefix(origin, "ws://")) {
		log.Fatal("-relay must be a wss:// origin (or ws:// with -allow-insecure)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for ctx.Err() == nil {
		if err := session(ctx, origin, id, priv, *model); err != nil && ctx.Err() == nil {
			log.Printf("disconnected: %v (retrying in 3s)", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
}

func loadOrCreate(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s is not PEM", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok || ek.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%s is not an EC P-256 key", path)
		}
		return ek, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return k, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func env(id string, typ protocol.MessageType, corr string, payload any) *protocol.Envelope {
	b, _ := json.Marshal(payload)
	now := time.Now().UTC()
	return &protocol.Envelope{V: protocol.Version, Type: typ, ID: protocol.NewID(), Corr: corr, Device: id, TS: &now, Payload: b}
}

func send(ctx context.Context, c *websocket.Conn, e *protocol.Envelope) error {
	b, err := e.Marshal()
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, b)
}

func recv(ctx context.Context, c *websocket.Conn) (*protocol.Envelope, error) {
	_, b, err := c.Read(ctx)
	if err != nil {
		return nil, err
	}
	return protocol.Parse(b)
}

func session(ctx context.Context, origin, id string, priv *ecdsa.PrivateKey, model string) error {
	c, _, err := websocket.Dial(ctx, origin+"/v1/device/ws", nil)
	if err != nil {
		return err
	}
	defer c.CloseNow()
	c.SetReadLimit(protocol.MaxMessageBytes)

	hello := env(id, protocol.TypeHello, "", protocol.HelloPayload{Versions: []int{1}, AppVersion: "simdevice"})
	if err := send(ctx, c, hello); err != nil {
		return err
	}
	ack, err := recv(ctx, c)
	if err != nil {
		return err
	}
	var ap protocol.HelloAckPayload
	if json.Unmarshal(ack.Payload, &ap) != nil {
		return fmt.Errorf("bad hello_ack")
	}
	nonce, err := base64.StdEncoding.DecodeString(ap.Nonce)
	if err != nil {
		return err
	}
	h := sha256.Sum256(protocol.AuthMessage(nonce, id, origin))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return err
	}
	if err := send(ctx, c, env(id, protocol.TypeAuth, "", protocol.AuthPayload{Signature: base64.StdEncoding.EncodeToString(sig)})); err != nil {
		return err
	}
	if err := send(ctx, c, env(id, protocol.TypeHeartbeat, "", struct{}{})); err != nil {
		return err
	}
	log.Printf("connected as %s", id)

	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = send(ctx, c, env(id, protocol.TypeHeartbeat, "", struct{}{}))
			}
		}
	}()
	for {
		m, err := recv(ctx, c)
		if err != nil {
			return err
		}
		if m.Type != protocol.TypeCommand {
			continue
		}
		var cp protocol.CommandPayload
		_ = json.Unmarshal(m.Payload, &cp)
		log.Printf("command %s (%s)", cp.Capability, m.ID)
		if cp.Capability == "device.info" && cp.Version == 1 {
			_ = send(ctx, c, env(id, protocol.TypeResult, m.ID, map[string]any{"status": "ok", "data": map[string]any{
				"manufacturer": "Androvia", "model": model, "android_release": "16", "sdk_int": 36, "security_patch": "2026-10-01", "supported_abis": []string{"arm64-v8a"},
			}}))
		} else {
			_ = send(ctx, c, env(id, protocol.TypeError, m.ID, map[string]any{"code": "unknown_capability", "message": "unknown capability or version"}))
		}
	}
}
