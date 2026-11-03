package spec

import (
	"strings"
	"testing"
	"time"
)

func TestErrorCodesMatchContract(t *testing.T) {
	// 逐字对齐 API.md §10 的清单：少一个或多一个都要在评审时被发现。
	want := map[ErrorCode]int{
		"BAD_REQUEST": 400, "FIELD_NOT_ALLOWED": 400, "CODE_FORMAT_INVALID": 400,
		"NICKNAME_INVALID": 400, "CHUNK_SIZE_INVALID": 400, "CHUNK_COUNT_MISMATCH": 400,
		"CHUNK_INDEX_OUT_OF_RANGE": 400, "LENGTH_MISMATCH": 400, "PRELUDE_DIGEST_MISMATCH": 400,
		"RANGE_UNSUPPORTED": 400, "SIZE_LIMIT_EXCEEDED": 400,
		"AUTH_MISSING": 401, "AUTH_SIGNATURE_INVALID": 401, "AUTH_CHALLENGE_INVALID": 401,
		"AUTH_CODE_MISMATCH":   401,
		"AUTH_TOKEN_STALE":     401,
		"AUTH_TOKEN_INVALID":   401,
		"AUTH_TOKEN_EXPIRED":   401,
		"SIG_INPUT_TOO_LONG":   400,
		"SIGNAL_PEER_MISMATCH": 403, "NOT_TRANSFER_PARTY": 403,
		"CODE_NOT_FOUND": 404, "TRANSFER_NOT_FOUND": 404, "CHUNK_NOT_FOUND": 404,
		"CODE_TAKEN": 409, "PUBKEY_TAKEN": 409, "PRELUDE_CONFLICT": 409, "CHUNK_CONFLICT": 409,
		"CHUNKS_MISSING": 409, "PRELUDE_MISSING": 409, "TRANSFER_NOT_READY": 409,
		"DOWNLOAD_NOT_STARTED": 409, "TRANSFER_STATE_CONFLICT": 409,
		"TRANSFER_REVOKED": 410, "TRANSFER_EXPIRED": 410, "TRANSFER_CONSUMED": 410,
		"PAYLOAD_TOO_LARGE": 413, "CONTENT_TYPE_UNSUPPORTED": 415,
		"RANGE_NOT_SATISFIABLE": 416, "CODE_LOCKED": 423, "RATE_LIMITED": 429,
		"INTERNAL": 500, "SERVICE_UNAVAILABLE": 503, "INSUFFICIENT_STORAGE": 507,
		"SIGNAL_TOO_LARGE": 400,
	}
	for code, status := range want {
		if got := code.Status(); got != status {
			t.Errorf("%s status = %d, want %d", code, got, status)
		}
		if code.Message() == "" {
			t.Errorf("%s has empty message", code)
		}
	}
	for _, code := range AllErrorCodes() {
		if _, ok := want[code]; !ok {
			t.Errorf("unexpected error code %s", code)
		}
	}
	for code := range want {
		found := false
		for _, c := range AllErrorCodes() {
			if c == code {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing error code %s", code)
		}
	}
}

func TestRoutes(t *testing.T) {
	routes := []string{
		PathConfig, PathChallenges, PathCodes, PathCode,
		PathTransfers, PathTransfer, PathPrelude, PathChunk,
		PathStatus, PathComplete, PathAck, PathRevoke, PathInbox, PathWS,
	}
	seen := map[string]bool{}
	for _, r := range routes {
		if !strings.HasPrefix(r, "/v1/") {
			t.Fatalf("route %q does not start with /v1/", r)
		}
		if seen[r] {
			t.Fatalf("duplicate route %q", r)
		}
		seen[r] = true
	}
	if PathChunk != "/v1/transfers/{transferId}/chunks/{index}" {
		t.Fatalf("chunk route = %q", PathChunk)
	}
}

func TestPathBuilders(t *testing.T) {
	if got := CodePath("AWQW"); got != "/v1/codes/AWQW" {
		t.Fatalf("CodePath = %q", got)
	}
	if got := ChunkPath("abc", 7); got != "/v1/transfers/abc/chunks/7" {
		t.Fatalf("ChunkPath = %q", got)
	}
	if got := PreludePath("abc"); got != "/v1/transfers/abc/prelude" {
		t.Fatalf("PreludePath = %q", got)
	}
}

func TestPurposeCodes(t *testing.T) {
	cases := map[string]byte{
		PurposeRegister:       0x01,
		PurposeNicknameUpdate: 0x02,
		PurposeTransferCreate: 0x03,
		PurposeTransferRevoke: 0x04,
		PurposeInboxList:      0x05,
		PurposeWSHello:        0x06,
		PurposeTransferAck:    0x07,
	}
	for name, code := range cases {
		if got := PurposeCode(name); got != code {
			t.Errorf("PurposeCode(%s) = %#x, want %#x", name, got, code)
		}
	}
	if PurposeCode("NOPE") != 0 {
		t.Error("unknown purpose must map to 0")
	}
	if len(AllPurposes()) != 7 {
		t.Fatalf("AllPurposes = %v", AllPurposes())
	}
}

func TestTerminalStates(t *testing.T) {
	for _, s := range []string{StateConsumed, StateRevoked, StateExpired} {
		if !IsTerminalState(s) {
			t.Fatalf("%s should be terminal", s)
		}
	}
	for _, s := range []string{StateUploading, StateReady, StateLeased, ""} {
		if IsTerminalState(s) {
			t.Fatalf("%s should not be terminal", s)
		}
	}
	if TerminalErrorCode(StateRevoked) != ErrTransferRevoked ||
		TerminalErrorCode(StateExpired) != ErrTransferExpired ||
		TerminalErrorCode(StateConsumed) != ErrTransferConsumed {
		t.Fatal("terminal error mapping mismatch")
	}
}

func TestFormatTime(t *testing.T) {
	parsed, err := time.Parse(time.RFC3339Nano, "2026-11-02T14:00:00.987654321Z")
	if err != nil {
		t.Fatal(err)
	}
	if got := FormatTime(parsed); got != "2026-11-02T14:00:00Z" {
		t.Fatalf("FormatTime = %q", got)
	}
}
