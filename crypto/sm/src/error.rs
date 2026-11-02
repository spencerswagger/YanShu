//! 统一错误类型。错误码是对 Web 侧 C ABI 的稳定契约（负数）。

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// 参数非法（空指针、长度越界、密钥长度不对）
    BadArgument,
    /// 输出缓冲区太小
    BufferTooSmall,
    /// 随机源不可用
    Rng,
    /// 加密包魔数不符
    BadMagic,
    /// 不支持的版本号（只接受 v1）
    UnsupportedVersion,
    /// suite / flags / reserved 非法
    BadFlags,
    /// 输入被截断
    Truncated,
    /// DK 封装记录非法
    BadKeyRecord,
    /// 签名记录非法
    BadSignatureRecord,
    /// 清单记录非法
    BadManifestRecord,
    /// 块序号不连续 / 越界
    BlockSequence,
    /// 块重复
    DuplicateBlock,
    /// 缺少块
    MissingBlock,
    /// 末块标志与块位置不符
    LastFlagMismatch,
    /// SM4-GCM tag 校验失败（密文被篡改）
    TagMismatch,
    /// 清单与包头 / 块不一致
    ManifestMismatch,
    /// 签名验签失败
    SignatureMismatch,
    /// 末尾有多余字节
    TrailingBytes,
    /// SM2 曲线点非法（不在曲线上 / 无穷远点）
    BadPoint,
    /// SM2 KDF 输出全零
    BadKdf,
    /// SM2 密文非法（C1 不在曲线上 / C3 校验失败）
    BadCiphertext,
    /// 用户码非法
    BadCode,
    /// 用户码连续撞码，重试耗尽
    CodeExhausted,
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
            Error::BadMagic => -4,
            Error::UnsupportedVersion => -5,
            Error::BadFlags => -6,
            Error::Truncated => -7,
            Error::BadKeyRecord => -8,
            Error::BadSignatureRecord => -9,
            Error::BadManifestRecord => -10,
            Error::BlockSequence => -11,
            Error::DuplicateBlock => -12,
            Error::MissingBlock => -13,
            Error::LastFlagMismatch => -14,
            Error::TagMismatch => -15,
            Error::ManifestMismatch => -16,
            Error::SignatureMismatch => -17,
            Error::TrailingBytes => -18,
            Error::BadPoint => -19,
            Error::BadKdf => -20,
            Error::BadCiphertext => -23,
            Error::BadCode => -21,
            Error::CodeExhausted => -22,
            Error::Internal => -99,
        }
    }

    /// 稳定的错误名（供 JS 侧日志使用）。
    pub fn name(self) -> &'static str {
        match self {
            Error::BadArgument => "BAD_ARGUMENT",
            Error::BufferTooSmall => "BUFFER_TOO_SMALL",
            Error::Rng => "RNG",
            Error::BadMagic => "BAD_MAGIC",
            Error::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Error::BadFlags => "BAD_FLAGS",
            Error::Truncated => "TRUNCATED",
            Error::BadKeyRecord => "BAD_KEY_RECORD",
            Error::BadSignatureRecord => "BAD_SIGNATURE_RECORD",
            Error::BadManifestRecord => "BAD_MANIFEST_RECORD",
            Error::BlockSequence => "BLOCK_SEQUENCE",
            Error::DuplicateBlock => "DUPLICATE_BLOCK",
            Error::MissingBlock => "MISSING_BLOCK",
            Error::LastFlagMismatch => "LAST_FLAG_MISMATCH",
            Error::TagMismatch => "TAG_MISMATCH",
            Error::ManifestMismatch => "MANIFEST_MISMATCH",
            Error::SignatureMismatch => "SIGNATURE_MISMATCH",
            Error::TrailingBytes => "TRAILING_BYTES",
            Error::BadPoint => "BAD_POINT",
            Error::BadKdf => "BAD_KDF",
            Error::BadCiphertext => "BAD_CIPHERTEXT",
            Error::BadCode => "BAD_CODE",
            Error::CodeExhausted => "CODE_EXHAUSTED",
            Error::Internal => "INTERNAL",
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
