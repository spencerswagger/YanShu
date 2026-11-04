//! `ys_alloc` / `ys_free` 的健壮性：释放长度**不再**决定堆块大小。
//!
//! 旧实现用 `Vec::from_raw_parts(ptr, 0, len)` 释放，若调用方传的长度与分配时不一致
//! （或 `Vec::with_capacity` 容量取整），dlmalloc 会拿到错误的 size → 堆损坏 →
//! 后续 `__rdl_dealloc` panic（Web 在 ≥80 MiB 的 prelude 上遇到的 `unreachable`）。

use yanshu_sm::ffi::{ys_alloc, ys_free};

#[test]
fn alloc_free_roundtrip_and_wrong_len_is_safe() {
    unsafe {
        // 正常往返
        let p = ys_alloc(1024);
        assert!(!p.is_null());
        core::ptr::write_bytes(p, 0xAB, 1024);
        ys_free(p, 1024);

        // 释放时传错长度：不得崩溃，也不得破坏堆
        for i in 0..400usize {
            let n = 3000 + i;
            let q = ys_alloc(n);
            assert!(!q.is_null());
            ys_free(q, n.saturating_sub(33)); // 故意不一致
        }
        // 之后仍能正常分配大块（堆元数据没坏）
        let big = ys_alloc(1 << 20);
        assert!(!big.is_null());
        core::ptr::write_bytes(big, 0x5A, 1 << 20);
        ys_free(big, 1 << 20);
    }
}
