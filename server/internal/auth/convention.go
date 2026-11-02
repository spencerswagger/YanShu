package auth

// 验签口径（从端侧源码读出来的，不再等口头确认）。
//
// 依据：分支 `feat/endcrypto-wasm` @ `95a24ace625ba6194a17c48ac7038ea8ae90b954`
//   - `crypto/sm/src/sm2.rs:21`   `DEFAULT_ID = b"1234567812345678"`
//   - `crypto/sm/src/sm2.rs:434`  `ZA = SM3(ENTL ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py)`，
//                                 `ENTL = len(ID) * 8`（16 字节 ID → `0x0080`，u16be）
//   - `crypto/sm/src/sm2.rs:449`  `e = SM3(ZA ‖ M)`，`M` 是**原始消息字节**
//   - `crypto/sm/src/sm2.rs:515`  `verify(pub64, msg, id, sig64)` 用上面这个 e
//   - `crypto/sm/src/ffi.rs:472`  `ys_sm2_verify(pub64, msg, msg_len, sig64)` —— 公钥 **64**、签名**裸 R‖S**
//   - `crypto/sm/src/ffi.rs:495`  `ys_sm2_verify_der(pub64, msg, msg_len, sig_der, sig_len)` ——
//                                 公钥 **64**、签名 **DER**；注释原文写着"服务端校验 X-YS-Signature 时用这个"
//
// 结论（服务端执行这一套）：
//  1. userID：固定 `1234567812345678`，不做协商、不从请求里取。
//  2. ZA：由 SM2 内部参与计算；**不拼进 SIG_INPUT**，也不单独上行。
//  3. SIG_INPUT：`YSAUTH1 ‖ PURPOSE(1) ‖ NONCE(32) ‖ 字段串` 的**原始字节**直接作为 M，
//     不预先再算一次 SM3（`e = SM3(ZA‖M)` 里的 SM3 是必然的那一次）。
//  4. 公钥：内核 ABI 收 64 字节 `X‖Y`；服务端存 65 字节 `0x04‖X‖Y`，调用前剥掉前缀。
//  5. 签名：`X-YS-Signature` 是 base64url(DER `SEQUENCE{r,s}`)，交给 `ys_sm2_verify_der`。
//
// 双向对账见 `wasm_bidirectional_test.go`：端侧签 → Go 验、Go 签 → 端侧验，两边都过。
