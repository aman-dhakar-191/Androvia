package ratelimit_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/aman-dhakar-191/androvia/relay/internal/ratelimit"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestLimitsPerKeyAndRecovers(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	l := ratelimit.New(3, time.Minute, 100, c.now)
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("attempt %d refused", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("limit not enforced")
	}
	if !l.Allow("b") {
		t.Fatal("one key's limit affected another")
	}
	c.t = c.t.Add(61 * time.Second)
	if !l.Allow("a") {
		t.Fatal("did not recover after the window")
	}
}

func TestRefusedAttemptsDoNotExtendTheWindow(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	l := ratelimit.New(1, time.Minute, 10, c.now)
	l.Allow("a")
	for i := 0; i < 50; i++ { // hammering while limited
		c.t = c.t.Add(time.Second)
		l.Allow("a")
	}
	c.t = c.t.Add(15 * time.Second) // 65 s after the one allowed attempt
	if !l.Allow("a") {
		t.Fatal("refused attempts kept the key locked out")
	}
}

func TestBoundedMemoryFailsClosed(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	l := ratelimit.New(5, time.Minute, 3, c.now)
	for i := 0; i < 3; i++ {
		if !l.Allow(fmt.Sprint("k", i)) {
			t.Fatal("refused under the cap")
		}
	}
	if l.Allow("new-key") {
		t.Fatal("new key accepted beyond the memory cap")
	}
	if !l.Allow("k0") {
		t.Fatal("an existing key must keep working")
	}
	c.t = c.t.Add(2 * time.Minute) // everything expired: space is reclaimed
	if !l.Allow("new-key") {
		t.Fatal("expired keys were not swept")
	}
}

func TestBlockedPeeksWithoutRecording(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	l := ratelimit.New(2, time.Minute, 10, c.now)
	for i := 0; i < 50; i++ {
		if l.Blocked("a") {
			t.Fatal("peeking recorded an attempt")
		}
	}
	l.Allow("a")
	l.Allow("a")
	if !l.Blocked("a") {
		t.Fatal("not blocked at the limit")
	}
	if l.Blocked("b") {
		t.Fatal("another key is blocked")
	}
	c.t = c.t.Add(2 * time.Minute)
	if l.Blocked("a") {
		t.Fatal("still blocked after the window")
	}
}
