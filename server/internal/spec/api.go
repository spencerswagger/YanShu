// Package spec 是雁书服务端「对外契约」的唯一权威来源。
//
// 规则（重要）：
//   - 所有对外的路径、JSON 字段名、HTTP 头、状态字符串、WebSocket 消息类型、
//     错误码，**必须**定义在本包；业务代码里不允许出现字面量路径或字段名。
//   - docs/API.md 冻结后，对齐工作**只改本包**（必要时同步 handlers 里对
//     spec 常量的引用），不碰业务逻辑。
//
// 当前状态：docs/API.md 尚未落盘。本包里的名字全部是骨架期**暂定**值，
// 每一处待对齐的点都用 `DRAFT(API.md)` 注释标出，清单见 docs/DRAFT-FIELDS.md。
package spec

import "time"

const (
	// APIVersion 是对外 API 的路径版本段。
	APIVersion = "v1"

	// Prefix 是全部业务接口的公共前缀。
	// DRAFT(API.md): 前缀是否带 /api、是否用 /v1 均待对齐。
	Prefix = "/api/v1"

	// DraftNote 打印在启动日志里，提醒当前契约未冻结。
	DraftNote = "wire contract is DRAFT: paths/fields/error codes pending docs/API.md"
)

// HTTP 路由模板。http.ServeMux（Go 1.22+ 模式路由）直接使用这些常量。
const (
	// 挑战与会话（无账号体系，身份即密钥对）。
	PathChallenges = Prefix + "/auth/challenges" // POST 下发 nonce
	PathSessions   = Prefix + "/auth/sessions"   // POST 用签名换会话令牌

	// 用户码。
	PathCodes = Prefix + "/codes"        // POST 注册（码由公钥派生）
	PathCode  = Prefix + "/codes/{code}" // GET 查询公钥+昵称；PATCH 改昵称
	PathInbox = Prefix + "/inbox"        // GET 收件列表（按接收方码）

	// 包与分块。
	PathPackages = Prefix + "/packages"                            // POST 创建包
	PathPackage  = Prefix + "/packages/{packageId}"                // GET 包元信息
	PathPrelude  = Prefix + "/packages/{packageId}/prelude"        // PUT/GET prelude
	PathChunks   = Prefix + "/packages/{packageId}/chunks"         // GET 全部块元信息（预留）
	PathChunk    = Prefix + "/packages/{packageId}/chunks/{index}" // PUT/GET 单块
	PathCommit   = Prefix + "/packages/{packageId}/commit"         // POST 完成标记/锁定
	PathProgress = Prefix + "/packages/{packageId}/progress"       // GET 续传进度
	PathAck      = Prefix + "/packages/{packageId}/ack"            // POST 接收确认（扣次数）
	PathRevoke   = Prefix + "/packages/{packageId}/revoke"         // POST 发送方撤回

	// 直传信令（本轮只留消息类型与 501 桩）。
	PathWS = Prefix + "/ws"

	// 运维。
	PathHealthz = "/healthz"
)

// 路径参数名。与模板里的 {xxx} 必须一致。
const (
	ParamCode      = "code"
	ParamPackageID = "packageId"
	ParamIndex     = "index"
)

// HTTP 头。
const (
	// HeaderAuthorization 承载 `Bearer <sessionToken>`。
	// DRAFT(API.md): 会话令牌放 Authorization 还是自定义头，待对齐。
	HeaderAuthorization = "Authorization"

	// HeaderContentDigest 是客户端声明的请求体摘要（小写 hex 的 SM3 或 SHA-256，
	// 由 X-Yanshu-Digest-Alg 指定）。服务端用于幂等比对与续传校验。
	// DRAFT(API.md): 头名与算法取值待对齐。
	HeaderContentDigest    = "X-Yanshu-Digest"
	HeaderContentDigestAlg = "X-Yanshu-Digest-Alg"

	// HeaderRequestID 由服务端回填，便于排障；请求可自带。
	HeaderRequestID = "X-Request-Id"

	// HeaderRetryAfter 在 429/423 时告知重试间隔（秒）。
	HeaderRetryAfter = "Retry-After"
)

// 媒体类型。
const (
	ContentTypeJSON   = "application/json; charset=utf-8"
	ContentTypeBinary = "application/octet-stream"
)

// 摘要算法取值（HeaderContentDigestAlg）。
// DRAFT(API.md): 是否需要这个头、默认算法是什么，待对齐。
const (
	DigestAlgSM3    = "sm3"
	DigestAlgSHA256 = "sha256"
)

// 挑战用途。服务端按用途校验签名对象，避免跨用途重放。
const (
	PurposeRegister = "register" // 注册码：签名覆盖公钥
	PurposeNickname = "nickname" // 改昵称：签名覆盖码+公钥+新昵称
	PurposeSession  = "session"  // 换会话：签名覆盖码+公钥
)

// 包状态。终结态一旦进入不可回退。
const (
	PackageUploading = "uploading" // 收块中，可写
	PackageReady     = "ready"     // 已 commit，可下载
	PackageExpired   = "expired"   // TTL 到期（终结）
	PackageRevoked   = "revoked"   // 发送方撤回（终结）
	PackageExhausted = "exhausted" // 下载次数用尽（终结）
	PackagePurged    = "purged"    // 密文已物理删除（终结后的墓碑态）
)

// 码状态（查询接口要能区分「不存在」与「已过期」）。
const (
	CodeActive  = "active"
	CodeExpired = "expired"
)

// IsTerminalPackageState 判定包是否已进入终结态（终结后块一律不可下载）。
func IsTerminalPackageState(state string) bool {
	switch state {
	case PackageExpired, PackageRevoked, PackageExhausted, PackagePurged:
		return true
	}
	return false
}

// DefaultMaxChunkSize / DefaultMaxChunkCount 对齐 CRYPTO-PACK §14 的格式上限。
const (
	DefaultMaxChunkSize  uint32 = 1 << 20 // 1 MiB（格式允许 [16, 1048576]）
	DefaultMaxChunkCount uint32 = 1 << 20
	MaxPreludeLen        uint32 = 8 << 20 // prelude 里含清单与签名，给 8 MiB 余量
)

// 契约内建的时间常量（可被配置覆盖）。
const (
	DefaultChallengeTTL = 5 * time.Minute
	DefaultSessionTTL   = 24 * time.Hour
	DefaultCodeTTL      = 30 * 24 * time.Hour
	DefaultPackageTTL   = 24 * time.Hour
)

// 以下是路径构造函数。测试与客户端 SDK 用它们拼 URL，避免各处手写模板。
func CodePath(code string) string           { return Prefix + "/codes/" + code }
func PackagePath(id string) string          { return Prefix + "/packages/" + id }
func PreludePath(id string) string          { return PackagePath(id) + "/prelude" }
func ChunkPath(id string, index int) string { return PackagePath(id) + "/chunks/" + itoa(index) }
func CommitPath(id string) string           { return PackagePath(id) + "/commit" }
func ProgressPath(id string) string         { return PackagePath(id) + "/progress" }
func AckPath(id string) string              { return PackagePath(id) + "/ack" }
func RevokePath(id string) string           { return PackagePath(id) + "/revoke" }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
