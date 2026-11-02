//! 统一错误类型。错误名与 `docs/CRYPTO-PACK.md` §13 的端侧错误码一一对应，
//! 错误码（负数）是 C ABI 的稳定契约。

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// 参数非法（空指针、长度越界）
    BadArgument,
    /// 输出缓冲区太小
    BufferTooSmall,
    /// 随机源不可用
    Rng,
    /// 魔数不是 `YSPK`
    MagicMismatch,
    /// 版本不是 1.0 / 未知算法 ID
    VersionUnsupported,
    /// 头部字段非法（HEADER_LEN、RESERVED、CHUNK_SIZE、SIG_LEN…）
    HeaderInvalid,
    /// 长度不自洽（分段长度、块数、包尾多余字节）
    LengthInconsistent,
    /// 未知算法 ID
    AlgUnsupported,
    /// FLAGS 保留位非 0
    FlagsUnknown,
    /// `FLAGS.SENDER_SIGNED == 0`
    Unsigned,
    /// SM2 解封失败
    KeyUnwrapFailed,
    /// 清单 GCM 认证失败
    ManifestAuthFailed,
    /// 清单结构非法
    ManifestInvalid,
    /// 签名非法 / 验签失败 / DER 非规范
    SignatureInvalid,
    /// 包里 SENDER_PUB 派生的码与元数据里的码不一致
    SenderMismatch,
    /// 块号不连续 / 重复 / 末块标志不符
    ChunkOrder,
    /// 块 GCM 认证失败
    ChunkAuthFailed,
    /// 缺块
    ChunkMissing,
    /// 明文块摘要与清单不符
    DigestMismatch,
    /// 用户码非法
    BadCode,
    /// 撞码重试耗尽
    CodeExhausted,
    /// SM2 曲线点非法
    BadPoint,
    /// SM2 密文非法（C3 不符）
    BadCiphertext,
    /// 内部一致性错误
    Internal,
}

impl Error {
    /// 稳定的 C ABI 错误码。
    pub fn code(self) -> i32 {
        match self {
            Error::BadArgument => -1,
            Error::BufferTooSmall => -2,
            Error::Rng => -3,
            Error::MagicMismatch => -4,
            Error::VersionUnsupported => -5,
            Error::HeaderInvalid => -6,
            Error::LengthInconsistent => -7,
            Error::AlgUnsupported => -8,
            Error::FlagsUnknown => -9,
            Error::Unsigned => -10,
            Error::KeyUnwrapFailed => -11,
            Error::ManifestAuthFailed => -12,
            Error::ManifestInvalid => -13,
            Error::SignatureInvalid => -14,
            Error::SenderMismatch => -15,
            Error::ChunkOrder => -16,
            Error::ChunkAuthFailed => -17,
            Error::ChunkMissing => -18,
            Error::DigestMismatch => -19,
            Error::BadCode => -20,
            Error::CodeExhausted => -21,
            Error::BadPoint => -22,
            Error::BadCiphertext => -23,
            Error::Internal => -99,
        }
    }

    /// 与契约 §13 一致的错误名（Web 侧直接拿去映射文案）。
    pub fn name(self) -> &'static str {
        match self {
            Error::BadArgument => "CRYPTO_BAD_ARGUMENT",
            Error::BufferTooSmall => "CRYPTO_BUFFER_TOO_SMALL",
            Error::Rng => "CRYPTO_RNG_FAILED",
            Error::MagicMismatch => "CRYPTO_MAGIC_MISMATCH",
            Error::VersionUnsupported => "CRYPTO_VERSION_UNSUPPORTED",
            Error::HeaderInvalid => "CRYPTO_HEADER_INVALID",
            Error::LengthInconsistent => "CRYPTO_LENGTH_INCONSISTENT",
            Error::AlgUnsupported => "CRYPTO_ALG_UNSUPPORTED",
            Error::FlagsUnknown => "CRYPTO_FLAGS_UNKNOWN",
            Error::Unsigned => "CRYPTO_UNSIGNED",
            Error::KeyUnwrapFailed => "CRYPTO_KEY_UNWRAP_FAILED",
            Error::ManifestAuthFailed => "CRYPTO_MANIFEST_AUTH_FAILED",
            Error::ManifestInvalid => "CRYPTO_MANIFEST_INVALID",
            Error::SignatureInvalid => "CRYPTO_SIGNATURE_INVALID",
            Error::SenderMismatch => "CRYPTO_SENDER_MISMATCH",
            Error::ChunkOrder => "CRYPTO_CHUNK_ORDER",
            Error::ChunkAuthFailed => "CRYPTO_CHUNK_AUTH_FAILED",
            Error::ChunkMissing => "CRYPTO_CHUNK_MISSING",
            Error::DigestMismatch => "CRYPTO_DIGEST_MISMATCH",
            Error::BadCode => "CRYPTO_CODE_INVALID",
            Error::CodeExhausted => "CRYPTO_CODE_EXHAUSTED",
            Error::BadPoint => "CRYPTO_CURVE_INVALID",
            Error::BadCiphertext => "CRYPTO_CIPHERTEXT_INVALID",
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
