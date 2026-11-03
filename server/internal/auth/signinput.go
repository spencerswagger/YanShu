package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// SignPrefix 是鉴权签名输入的域分隔串（API.md §1.3）。
const SignPrefix = "YSAUTH1"

// PackSignPrefix 是**包签名**的域分隔串（CRYPTO-PACK §10.2）。
//
// 服务端只验认证签名（YSAUTH1），从不构造包签名（YSSIG1）；这里保留常量只为明确
// "两个域不可混用"，并让测试能断言两者不同。误用会让验签永远失败且很难查。
const PackSignPrefix = "YSSIG1"

// SignInput 长度约束。
const (
	NonceLen      = 32
	TransferIDLen = 32 // ASCII 小写 hex
)

var (
	// ErrSignInput 表示 SIG_INPUT 的字段不合法（长度/格式），属服务端内部参数错误。
	ErrSignInput = errors.New("auth: invalid sign input")
	transferIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// BuildSignInput 按 API.md §1.3 拼签名输入：
//
//	SIGN_PREFIX(7) ‖ PURPOSE(1) ‖ NONCE(32) ‖ <该用途的字段串>
func BuildSignInput(purposeCode byte, nonce, fields []byte) []byte {
	out := make([]byte, 0, len(SignPrefix)+1+NonceLen+len(fields))
	out = append(out, SignPrefix...)
	out = append(out, purposeCode)
	out = append(out, nonce...)
	out = append(out, fields...)
	return out
}

// codeField 校验并写入 CODE(4 ASCII)。
func codeField(dst []byte, code string) ([]byte, error) {
	if len(code) != 4 {
		return nil, fmt.Errorf("%w: code must be 4 bytes", ErrSignInput)
	}
	return append(dst, code...), nil
}

// RegisterFields：CODE(4) ‖ PUBKEY(65)。
func RegisterFields(code string, pubKey []byte) ([]byte, error) {
	if len(pubKey) != 65 {
		return nil, fmt.Errorf("%w: public key must be 65 bytes", ErrSignInput)
	}
	buf := make([]byte, 0, 4+65)
	buf, err := codeField(buf, code)
	if err != nil {
		return nil, err
	}
	return append(buf, pubKey...), nil
}

// NicknameUpdateFields：CODE(4) ‖ u16be(NICK_LEN) ‖ NICKNAME(UTF-8)。
func NicknameUpdateFields(code, nickname string) ([]byte, error) {
	if len(nickname) == 0 || len(nickname) > 0xffff {
		return nil, fmt.Errorf("%w: nickname length", ErrSignInput)
	}
	buf := make([]byte, 0, 4+2+len(nickname))
	buf, err := codeField(buf, code)
	if err != nil {
		return nil, err
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(nickname)))
	return append(buf, nickname...), nil
}

// TransferCreateFields：
//
//	SENDER_CODE(4) ‖ RECIPIENT_CODE(4) ‖ u64be(PLAINTEXT_SIZE)
//	‖ u32be(CHUNK_SIZE) ‖ u32be(CHUNK_COUNT) ‖ u32be(PRELUDE_LEN) ‖ PRELUDE_SM3(32)
func TransferCreateFields(senderCode, recipientCode string, plaintextSize uint64, chunkSize, chunkCount, preludeLen uint32, preludeSM3 []byte) ([]byte, error) {
	if len(preludeSM3) != 32 {
		return nil, fmt.Errorf("%w: prelude_sm3 must be 32 bytes", ErrSignInput)
	}
	buf := make([]byte, 0, 4+4+8+4*3+32)
	var err error
	if buf, err = codeField(buf, senderCode); err != nil {
		return nil, err
	}
	if buf, err = codeField(buf, recipientCode); err != nil {
		return nil, err
	}
	buf = binary.BigEndian.AppendUint64(buf, plaintextSize)
	buf = binary.BigEndian.AppendUint32(buf, chunkSize)
	buf = binary.BigEndian.AppendUint32(buf, chunkCount)
	buf = binary.BigEndian.AppendUint32(buf, preludeLen)
	return append(buf, preludeSM3...), nil
}

// TransferRevokeFields：SENDER_CODE(4) ‖ TRANSFER_ID(32 ASCII)。
func TransferRevokeFields(senderCode, transferID string) ([]byte, error) {
	return codeAndTransferID(senderCode, transferID)
}

// TransferAckFields：RECEIVER_CODE(4) ‖ TRANSFER_ID(32 ASCII)。
func TransferAckFields(receiverCode, transferID string) ([]byte, error) {
	return codeAndTransferID(receiverCode, transferID)
}

func codeAndTransferID(code, transferID string) ([]byte, error) {
	if !transferIDRe.MatchString(transferID) {
		return nil, fmt.Errorf("%w: transfer_id must be 32 lowercase hex", ErrSignInput)
	}
	buf := make([]byte, 0, 4+TransferIDLen)
	buf, err := codeField(buf, code)
	if err != nil {
		return nil, err
	}
	return append(buf, transferID...), nil
}

// InboxListFields：CODE(4)。
func InboxListFields(code string) ([]byte, error) {
	buf := make([]byte, 0, 4)
	return codeField(buf, code)
}

// WSHelloFields：CODE(4)。
func WSHelloFields(code string) ([]byte, error) {
	buf := make([]byte, 0, 4)
	return codeField(buf, code)
}

// BuildForPurpose 是给 handler 的统一入口：按 PURPOSE 构造 SIG_INPUT。
// 参数用 any 会丢类型安全，这里按用途拆成显式函数，handler 各自调用。
func PurposeName(code byte) string {
	switch code {
	case spec.PurposeCodeRegister:
		return spec.PurposeRegister
	case spec.PurposeCodeNicknameUpdate:
		return spec.PurposeNicknameUpdate
	case spec.PurposeCodeTransferCreate:
		return spec.PurposeTransferCreate
	case spec.PurposeCodeTransferRevoke:
		return spec.PurposeTransferRevoke
	case spec.PurposeCodeInboxList:
		return spec.PurposeInboxList
	case spec.PurposeCodeWSHello:
		return spec.PurposeWSHello
	case spec.PurposeCodeTransferAck:
		return spec.PurposeTransferAck
	}
	return ""
}
