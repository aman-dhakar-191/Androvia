// Package policy is the single authorization engine. REST handlers (and later the MCP gateway) call it; nothing else
// decides who may do what. Deny by default: a client can do only what an explicit grant on that device allows.
//
// Scope vocabulary (no wildcards, on purpose):
//
//	devices:read                       see a device and whether it is online
//	capability:<capability id>:execute run that one capability on that device
package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

const (
	ScopeDevicesRead  = "devices:read"
	MaxScopesPerGrant = 64
)

var (
	// ErrForbidden means the client has no grant that allows the action.
	ErrForbidden = errors.New("forbidden")

	capabilityRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	executeRE    = regexp.MustCompile(`^capability:([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+):execute$`)
)

// ExecuteScope is the scope needed to run capability on a device. It returns "" for an invalid capability id so a
// malformed id can never match a grant.
func ExecuteScope(capability string) string {
	if !capabilityRE.MatchString(capability) {
		return ""
	}
	return "capability:" + capability + ":execute"
}

// ValidScope reports whether s is a scope this relay understands.
func ValidScope(s string) bool { return s == ScopeDevicesRead || executeRE.MatchString(s) }

// NormalizeScopes validates, de-duplicates and sorts. An unknown scope is an error, never silently dropped.
func NormalizeScopes(in []string) ([]string, error) {
	if len(in) > MaxScopesPerGrant {
		return nil, fmt.Errorf("at most %d scopes per grant", MaxScopesPerGrant)
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !ValidScope(s) {
			return nil, fmt.Errorf("unknown scope %q", s)
		}
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Source supplies the scopes granted to a client on a device.
type Source interface {
	ScopesFor(ctx context.Context, clientID, deviceID string) ([]string, error)
}

type Authorizer struct{ src Source }

func NewAuthorizer(src Source) *Authorizer { return &Authorizer{src: src} }

// Require returns nil only if the client holds scope on the device. Lookup errors are returned as-is (fail closed).
func (a *Authorizer) Require(ctx context.Context, clientID, deviceID, scope string) error {
	if clientID == "" || deviceID == "" || scope == "" {
		return ErrForbidden
	}
	have, err := a.src.ScopesFor(ctx, clientID, deviceID)
	if err != nil {
		return err
	}
	for _, s := range have {
		if s == scope {
			return nil
		}
	}
	return ErrForbidden
}

// HasAny reports whether the client holds any grant at all on the device (used to avoid revealing devices the client
// has no relationship with).
func (a *Authorizer) HasAny(ctx context.Context, clientID, deviceID string) (bool, error) {
	if clientID == "" || deviceID == "" {
		return false, nil
	}
	have, err := a.src.ScopesFor(ctx, clientID, deviceID)
	return len(have) > 0, err
}
