// Package ratelimit is a small in-memory sliding-window limiter for unauthenticated endpoints.
package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	hits   map[string][]time.Time
	maxKey int
}

// New allows at most limit events per key per window. maxKeys bounds memory: when exceeded, expired keys are swept
// and, if still full, new keys are refused (fail closed).
func New(limit int, window time.Duration, maxKeys int, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{limit: limit, window: window, now: now, hits: map[string][]time.Time{}, maxKey: maxKeys}
}

// Allow records an attempt and reports whether it is within the limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)
	ts, known := l.hits[key]
	if !known && len(l.hits) >= l.maxKey {
		l.sweep(cutoff)
		if len(l.hits) >= l.maxKey {
			return false
		}
	}
	kept := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

func (l *Limiter) sweep(cutoff time.Time) {
	for k, ts := range l.hits {
		if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
			delete(l.hits, k)
		}
	}
}
