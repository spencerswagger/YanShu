package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 白名单是"运行时真拦人"的那一份，它的展示串被写进两处错误文案
// （`-verify-kernel` 与启动校验的 "not in the frozen allowlist (expected …)"）。
// 早先用 `for k := range map { return k }`，map 迭代顺序随机 → 同一份输入两次跑出
// 不同的"期望 sha"（2/3 概率给回滚版/灰度版），既把人往错方向指也没法 grep。
// 下面几条把"顺序固定 + 首条=当前 + 与仓库产物一致"钉死。

// TestFrozenKernelWhitelistMatchesOrder：有序视图与 map 必须一一对应，别一边加了一条另一边漏。
func TestFrozenKernelWhitelistMatchesOrder(t *testing.T) {
	if len(frozenKernelOrder) != len(FrozenKernelSHA256) {
		t.Fatalf("白名单条数不一致：order=%d map=%d", len(frozenKernelOrder), len(FrozenKernelSHA256))
	}
	for _, k := range frozenKernelOrder {
		if !FrozenKernelSHA256[k.SHA256] {
			t.Fatalf("order 里的 %s 不在 FrozenKernelSHA256 里", k.SHA256)
		}
		if len(k.SHA256) != 64 {
			t.Fatalf("sha256 长度不是 64：%s", k.SHA256)
		}
		if k.Bytes <= 0 || k.Role == "" {
			t.Fatalf("白名单条目缺字节数或用途：%+v", k)
		}
	}
	if len(FrozenKernelSHA256) != 3 {
		t.Fatalf("当前应有 3 条（当前/回滚/灰度），实际 %d 条", len(FrozenKernelSHA256))
	}
}

// TestCurrentKernelIsFirstAndShipsInRepo：首条必须是"当前"角色，且等于仓库里那份 wasm 的 sha256。
// 这条能挡住"换了内核却没改白名单首条"和"白名单首条指向旧版"两种错法。
func TestCurrentKernelIsFirstAndShipsInRepo(t *testing.T) {
	if role := frozenKernelOrder[0].Role; role != "当前" {
		t.Fatalf("白名单首条的用途应为「当前」，实际「%s」", role)
	}
	if got, want := CurrentFrozenKernelSHA256(), frozenKernelOrder[0].SHA256; got != want {
		t.Fatalf("CurrentFrozenKernelSHA256()=%s，order[0]=%s", got, want)
	}

	path := filepath.Join("..", "..", "kernel", "yanshu_sm.wasm")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("跳过与仓库产物比对（读不到 %s：%v）", path, err)
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if got != CurrentFrozenKernelSHA256() {
		t.Fatalf("仓库内 %s 的 sha256=%s，与白名单首条（当前内核）%s 不一致：\n"+
			"换了内核就要同步改 frozenKernelOrder 首条（并在 docs/CRYPTO-PACK.md §18.2 记字节数与导出数）",
			path, got, CurrentFrozenKernelSHA256())
	}
	if want := frozenKernelOrder[0].Bytes; len(raw) != want {
		t.Fatalf("仓库内内核 %d B，白名单首条记的是 %d B", len(raw), want)
	}
}

// TestFrozenKernelListIsDeterministicAndComplete：展示串必须稳定、包含三版、且首段是当前内核。
func TestFrozenKernelListIsDeterministicAndComplete(t *testing.T) {
	first := FrozenKernelSHA256List()
	if first == "" {
		t.Fatal("展示串为空")
	}
	for i := 0; i < 200; i++ {
		if got := FrozenKernelSHA256List(); got != first {
			t.Fatalf("展示串不稳定：第 %d 次得到 %q，首次是 %q", i, got, first)
		}
	}
	for _, k := range frozenKernelOrder {
		short := k.SHA256[:8]
		if !strings.Contains(first, short) {
			t.Fatalf("展示串漏了 %s…：%q", short, first)
		}
		if !strings.Contains(first, "("+k.Role+")") {
			t.Fatalf("展示串没标出「%s」这条：%q", k.Role, first)
		}
	}
	currentShort := CurrentFrozenKernelSHA256()[:8]
	if !strings.HasPrefix(first, currentShort+"…(当前)") {
		t.Fatalf("展示串应以当前内核开头，实际：%q", first)
	}
}
