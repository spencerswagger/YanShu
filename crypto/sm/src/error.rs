//! 统一错误类型。
//!
//! **名字是唯一权威，数值只作兼容**（契约 `CRYPTO-PACK §13.1`）。
//!
//! * `name()` 返回契约错误名 `CRYPTO_*`；ABI 的 `ys_error_name` / `ys_error_name_v1`
//!   都返回这一套，与 Rust 侧逐字一致。
//! * 数值按契约 §13.1 分配：首版重复的值降为**别名**——`-11/-12/-14→-28`、
//!   `-13→-30`、`-15→-29`、`-16→-31`、`-20/-23→-19`；`-19` 归
//!   `CRYPTO_CIPHERTEXT_INVALID`，`CRYPTO_CURVE_INVALID` 用新值 `-34`；
//!   `-99` 保留给内部错误。
//! * 旧数值仍能被 `ys_error_name()` 解析（见 `ALIASES`），但**不再产出**：
//!   日志、测试、判定一律用名字。

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    // ---- 首版 ABI 的变体（数值与名字都不动，rune-v1 布局继续用它们）
    BadArgument,
    BufferTooSmall,
    Rng,
    BadMagic,
    UnsupportedVersion,
    BadFlags,
    Truncated,
    BadKeyRecord,
    BadSignatureRecord,
    BadManifestRecord,
    BlockSequence,
    DuplicateBlock,
    MissingBlock,
    LastFlagMismatch,
    TagMismatch,
    ManifestMismatch,
    SignatureMismatch,
    TrailingBytes,
    BadPoint,
    BadKdf,
    BadCode,
    CodeExhausted,
    BadCiphertext,

    // ---- 契约 §13 需要的细粒度（新槽位，-24 起；老调用方只会看到"未知码"）
    HeaderInvalid,
    AlgUnsupported,
    Unsigned,
    LengthInconsistent,
    ChunkOrder,
    ChunkAuthFailed,
    ChunkMissing,
    ManifestAuthFailed,
    DigestMismatch,
    SenderMismatch,

    Internal,
}

impl Error {
    /// 数值错误码：**-4..-23 与首版完全一致**，新增从 -24 起。
    pub fn code(self) -> i32 {
        match self {
            Error::BadArgument => -1,
            Error::BufferTooSmall => -2,
            Error::Rng => -3,
            Error::BadMagic => -4,
            Error::UnsupportedVersion => -5,
            Error::BadFlags => -6,
            // CRYPTO_TRUNCATED（首版 -7 正名）
            Error::Truncated => -7,
            Error::BadKeyRecord => -8,
            Error::BadSignatureRecord => -9,
            Error::BadManifestRecord => -10,
            // 首版重复值 → 规范值（-11/-12/-14 → -28，-13 → -30，-15 → -29，-16 → -31）
            Error::BlockSequence => -28,
            Error::DuplicateBlock => -28,
            Error::MissingBlock => -30,
            Error::LastFlagMismatch => -28,
            Error::TagMismatch => -29,
            Error::ManifestMismatch => -31,
            Error::SignatureMismatch => -17,
            Error::TrailingBytes => -18,
            // 契约把 -19 定为 CRYPTO_CIPHERTEXT_INVALID；曲线错误改用 -34
            Error::BadKdf => -19,
            Error::BadCiphertext => -19,
            Error::BadPoint => -34,
            Error::BadCode => -21,
            Error::CodeExhausted => -22,
            Error::HeaderInvalid => -24,
            Error::AlgUnsupported => -25,
            Error::Unsigned => -26,
            Error::LengthInconsistent => -27,
            Error::ChunkOrder => -28,
            Error::ChunkAuthFailed => -29,
            Error::ChunkMissing => -30,
            Error::ManifestAuthFailed => -31,
            Error::DigestMismatch => -32,
            Error::SenderMismatch => -33,
            Error::Internal => -99,
        }
    }

    /// 契约 §13 的端侧错误名（Gate 探针/日志用这套）。
    pub fn name(self) -> &'static str {
        match self {
            Error::BadArgument => "CRYPTO_BAD_ARGUMENT",
            Error::BufferTooSmall => "CRYPTO_BUFFER_TOO_SMALL",
            Error::Rng => "CRYPTO_RNG_FAILED",
            Error::BadMagic => "CRYPTO_MAGIC_MISMATCH",
            Error::UnsupportedVersion => "CRYPTO_VERSION_UNSUPPORTED",
            Error::BadFlags => "CRYPTO_FLAGS_UNKNOWN",
            Error::Truncated => "CRYPTO_TRUNCATED",
            Error::BadKeyRecord => "CRYPTO_KEY_UNWRAP_FAILED",
            Error::BadSignatureRecord => "CRYPTO_SIGNATURE_INVALID",
            Error::BadManifestRecord => "CRYPTO_MANIFEST_INVALID",
            Error::BlockSequence => "CRYPTO_CHUNK_ORDER",
            Error::DuplicateBlock => "CRYPTO_CHUNK_ORDER",
            Error::MissingBlock => "CRYPTO_CHUNK_MISSING",
            Error::LastFlagMismatch => "CRYPTO_CHUNK_ORDER",
            Error::TagMismatch => "CRYPTO_CHUNK_AUTH_FAILED",
            Error::ManifestMismatch => "CRYPTO_MANIFEST_AUTH_FAILED",
            Error::SignatureMismatch => "CRYPTO_SIGNATURE_INVALID",
            Error::TrailingBytes => "CRYPTO_TRAILING_BYTES",
            Error::BadPoint => "CRYPTO_CURVE_INVALID",
            Error::BadKdf => "CRYPTO_CIPHERTEXT_INVALID",
            Error::BadCode => "CRYPTO_CODE_INVALID",
            Error::CodeExhausted => "CRYPTO_CODE_EXHAUSTED",
            Error::BadCiphertext => "CRYPTO_CIPHERTEXT_INVALID",
            Error::HeaderInvalid => "CRYPTO_HEADER_INVALID",
            Error::AlgUnsupported => "CRYPTO_ALG_UNSUPPORTED",
            Error::Unsigned => "CRYPTO_UNSIGNED",
            Error::LengthInconsistent => "CRYPTO_LENGTH_INCONSISTENT",
            Error::ChunkOrder => "CRYPTO_CHUNK_ORDER",
            Error::ChunkAuthFailed => "CRYPTO_CHUNK_AUTH_FAILED",
            Error::ChunkMissing => "CRYPTO_CHUNK_MISSING",
            Error::ManifestAuthFailed => "CRYPTO_MANIFEST_AUTH_FAILED",
            Error::DigestMismatch => "CRYPTO_DIGEST_MISMATCH",
            Error::SenderMismatch => "CRYPTO_SENDER_MISMATCH",
            Error::Internal => "CRYPTO_INTERNAL",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.code())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
