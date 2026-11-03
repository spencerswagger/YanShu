//! 契约 §13.1 的错误名/数值：名字是唯一权威，首版重复值只作别名。

use yanshu_sm::error::Error;

#[test]
fn canonical_numbers_and_aliases() {
    // 契约的规范值
    assert_eq!(Error::Truncated.code(), -7); // CRYPTO_TRUNCATED
    assert_eq!(Error::TrailingBytes.code(), -18);
    assert_eq!(Error::LengthInconsistent.code(), -27);
    assert_eq!(Error::ChunkOrder.code(), -28);
    assert_eq!(Error::ChunkAuthFailed.code(), -29);
    assert_eq!(Error::ChunkMissing.code(), -30);
    assert_eq!(Error::ManifestAuthFailed.code(), -31);
    assert_eq!(Error::DigestMismatch.code(), -32);
    assert_eq!(Error::SenderMismatch.code(), -33);
    assert_eq!(Error::BadKdf.code(), -19);
    assert_eq!(Error::BadCiphertext.code(), -19);
    assert_eq!(Error::BadPoint.code(), -34);
    assert_eq!(Error::Internal.code(), -99);

    // 首版重复值 → 别名（同一个规范数值）
    assert_eq!(Error::BlockSequence.code(), -28);
    assert_eq!(Error::DuplicateBlock.code(), -28);
    assert_eq!(Error::LastFlagMismatch.code(), -28);
    assert_eq!(Error::MissingBlock.code(), -30);
    assert_eq!(Error::TagMismatch.code(), -29);
    assert_eq!(Error::ManifestMismatch.code(), -31);
}

#[test]
fn names_are_unique_per_category() {
    // 块序 / 清单 / 截断 / 缺块 / 版本 / tag 六类必须能区分
    assert_eq!(Error::ChunkOrder.name(), "CRYPTO_CHUNK_ORDER");
    assert_eq!(Error::ChunkMissing.name(), "CRYPTO_CHUNK_MISSING");
    assert_eq!(Error::ChunkAuthFailed.name(), "CRYPTO_CHUNK_AUTH_FAILED");
    assert_eq!(
        Error::ManifestAuthFailed.name(),
        "CRYPTO_MANIFEST_AUTH_FAILED"
    );
    assert_eq!(
        Error::ManifestMismatch.name(),
        "CRYPTO_MANIFEST_AUTH_FAILED"
    );
    assert_eq!(Error::Truncated.name(), "CRYPTO_TRUNCATED");
    assert_eq!(Error::TrailingBytes.name(), "CRYPTO_TRAILING_BYTES");
    assert_eq!(
        Error::LengthInconsistent.name(),
        "CRYPTO_LENGTH_INCONSISTENT"
    );
    assert_eq!(
        Error::UnsupportedVersion.name(),
        "CRYPTO_VERSION_UNSUPPORTED"
    );
    assert_eq!(Error::TagMismatch.name(), "CRYPTO_CHUNK_AUTH_FAILED");

    // 别名与规范变体同名（名字唯一权威）
    assert_eq!(Error::BlockSequence.name(), Error::ChunkOrder.name());
    assert_eq!(Error::MissingBlock.name(), Error::ChunkMissing.name());
    assert_eq!(Error::TagMismatch.name(), Error::ChunkAuthFailed.name());
    assert_eq!(
        Error::ManifestMismatch.name(),
        Error::ManifestAuthFailed.name()
    );
    assert_eq!(Error::BadKdf.name(), Error::BadCiphertext.name());

    // 三个"长度类"必须互不相同
    let names = [
        Error::Truncated.name(),
        Error::TrailingBytes.name(),
        Error::LengthInconsistent.name(),
    ];
    assert_ne!(names[0], names[1]);
    assert_ne!(names[1], names[2]);
    assert_ne!(names[0], names[2]);
}
