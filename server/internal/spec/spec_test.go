package spec

import (
	"strings"
	"testing"
)

func TestErrorCodesAreComplete(t *testing.T) {
	seen := map[ErrorCode]bool{}
	for _, c := range AllErrorCodes() {
		if seen[c] {
			t.Fatalf("duplicate code %s", c)
		}
		seen[c] = true
		if c.Message() == "" || c.Message() == errMessage[ErrInternal] && c != ErrInternal {
			t.Fatalf("code %s has no message", c)
		}
		if c.Status() < 400 || c.Status() > 599 {
			t.Fatalf("code %s has non-error status %d", c, c.Status())
		}
	}
	for _, want := range []ErrorCode{
		ErrCodeNotFound, ErrCodeExpired, ErrCodeTaken,
		ErrPackageExpired, ErrPackageRevoked, ErrPackageExhausted, ErrPackagePurged,
		ErrChunkConflict, ErrPackageLocked, ErrRateLimited, ErrLockedOut,
		ErrVerifierUnavailable, ErrForbidden,
	} {
		if !seen[want] {
			t.Fatalf("missing required error code %s", want)
		}
	}
}

func TestRoutesAreUniqueAndPrefixed(t *testing.T) {
	routes := []string{
		PathChallenges, PathSessions, PathCodes, PathCode, PathInbox,
		PathPackages, PathPackage, PathPrelude, PathChunks, PathChunk,
		PathCommit, PathProgress, PathAck, PathRevoke, PathWS,
	}
	seen := map[string]bool{}
	for _, r := range routes {
		if !strings.HasPrefix(r, Prefix) {
			t.Fatalf("route %q does not start with %q", r, Prefix)
		}
		if seen[r] {
			t.Fatalf("duplicate route %q", r)
		}
		seen[r] = true
	}
	if !strings.HasPrefix(PathHealthz, "/") {
		t.Fatalf("healthz route = %q", PathHealthz)
	}
}

func TestPathBuilders(t *testing.T) {
	if got := CodePath("AWQW"); got != "/api/v1/codes/AWQW" {
		t.Fatalf("CodePath = %q", got)
	}
	if got := ChunkPath("abc", 7); got != "/api/v1/packages/abc/chunks/7" {
		t.Fatalf("ChunkPath = %q", got)
	}
	if got := ProgressPath("abc"); got != "/api/v1/packages/abc/progress" {
		t.Fatalf("ProgressPath = %q", got)
	}
}

func TestTerminalStates(t *testing.T) {
	for _, s := range []string{PackageExpired, PackageRevoked, PackageExhausted, PackagePurged} {
		if !IsTerminalPackageState(s) {
			t.Fatalf("%s should be terminal", s)
		}
	}
	for _, s := range []string{PackageUploading, PackageReady, ""} {
		if IsTerminalPackageState(s) {
			t.Fatalf("%s should not be terminal", s)
		}
	}
}
