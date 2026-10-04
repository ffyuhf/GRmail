// 向导 DKIM 密钥生成链测试（向导占位符与布局修复批次）。
// 覆盖：四档强度生成→私钥 PKCS#8 落盘→SignerService 加载+签名（消费兼容锚——
// 失败判定 2）→DKIMPublicKeyDNSValue 步 4 呈现路径往返（TXT 形态裁决六a）。
// SRS 条目：FR-015（3.9.2）/FR-008（3.4.1）；TC-015/TC-008 关联锚。
// 依据：向导占位符与布局修复计划书 v1.0.0 第三章阶段 2 检查点，G2 批准 2026-10-04 15:03:25。
// 修改历史：
//
//	2026-10-04 15:08:00 | 新建 | 向导占位符与布局修复批次（计划书阶段 2）
package auth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"GRmail/internal/config"
)

// TestGenerateDKIMKeyPair 四档强度全链验证：生成→Signer 加载→签名→DNS TXT 往返。
func TestGenerateDKIMKeyPair(t *testing.T) {
	for _, strength := range DKIMStrengths {
		t.Run(strength, func(t *testing.T) {
			privPEM, dnsTXT, algorithm, err := GenerateDKIMKeyPair(strength)
			if err != nil {
				t.Fatalf("密钥生成失败: %v", err)
			}
			// 私钥落盘临时文件→SignerService 加载（PKCS#8 消费兼容——reloadKey 同路径）
			path := filepath.Join(t.TempDir(), "dkim.pem")
			if err := os.WriteFile(path, privPEM, 0o600); err != nil {
				t.Fatalf("私钥落盘失败: %v", err)
			}
			svc, err := NewSignerService(config.DKIMConf{
				Selector: "grmail", KeyPath: path, Algorithm: algorithm,
			})
			if err != nil {
				t.Fatalf("Signer 加载失败（生成格式与消费格式不兼容）: %v", err)
			}
			msg := []byte("From: a@example.com\r\nSubject: t\r\n\r\nbody\r\n")
			if _, err := svc.Sign(context.Background(), msg, "example.com"); err != nil {
				t.Fatalf("签名失败: %v", err)
			}
			// DNS TXT 形态断言（裁决六a：v=DKIM1; k=rsa|ed25519; p=Base64(SPKI)）
			wantK := "rsa"
			if strength == "ed25519" {
				wantK = "ed25519"
			}
			wantPrefix := "v=DKIM1; k=" + wantK + "; p="
			// p= 段长度下限 40：rsa SPKI(b64)≈392 字符、ed25519 SPKI(b64)=68 字符均覆盖
			if !strings.HasPrefix(dnsTXT, wantPrefix) || len(dnsTXT) < len(wantPrefix)+40 {
				t.Fatalf("TXT 形态不符: %.60s…（长度 %d）", dnsTXT, len(dnsTXT))
			}
			// 步 4 呈现路径往返：DKIMPublicKeyDNSValue 读同一文件产出一致值
			got, err := DKIMPublicKeyDNSValue(path)
			if err != nil || got != dnsTXT {
				t.Fatalf("TXT 往返不一致: err=%v 相等=%v", err, got == dnsTXT)
			}
		})
	}
	// 非法档位拒绝（三档 rsa 与 ed25519 之外的值域——ErrUnsupportedAlgorithm）
	if _, _, _, err := GenerateDKIMKeyPair("rsa-512"); err == nil {
		t.Fatal("非法强度档位应拒绝")
	}
	// 未配置空路径：返回空串（向导该行不呈现——零占位语义）
	if txt, err := DKIMPublicKeyDNSValue(""); err != nil || txt != "" {
		t.Fatalf("空路径应返回空串: txt=%q err=%v", txt, err)
	}
}
