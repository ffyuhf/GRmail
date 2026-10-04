// main 包 U5 装配适配器（架构第四章依赖方向的落地窄化：
// mail 域经窄接口消费，DB 查询细节收敛于 cmd 装配层——业务层不触 SQL 的分层例外仅限
// 此适配层，其查询服务于 mail 域注入位）。
// 依据：U5 计划书 v1.0.0 步骤 11（1.5⑨管理员豁免经 users 表；1.5⑥⑧消息源读取）；
// U13 计划书 v1.0.0 步骤 9（daneValidatorAdapter——mail 零 transport import 的
// 类型桥接，契约 v1.9.0 2.3 注入形态）；传输安全与日志增强批次（stsValidatorAdapter
// +tlsrptRecorderAdapter——契约 v1.21.0 2.3 注入形态，沿 daneValidatorAdapter 先例）。
// 修改历史：
//
//	2026-09-17 23:36:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 11 配套装配）
//	2026-09-23 08:55:00 | 扩展 | U13 传输安全全量：daneValidatorAdapter（计划书步骤 9）
//	2026-10-01 23:28:00 | 扩展 | 传输安全与日志增强批次 L-A/L-B：stsValidatorAdapter
//	+tlsrptRecorderAdapter（G2 批准 2026-10-01 22:54:41，计划书步骤 2/3 装配配套）
package main

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"

	"GRmail/internal/auth"
	"GRmail/internal/mail"
	"GRmail/internal/storage"
	"GRmail/internal/transport"
)

// adminLookupAdapter mail.adminLookup 的正规化适配（FR-002：users 表 is_admin 豁免判定；
// U10 Q9-A 收敛：U5 裸 SQL 数据源替换为 storage.UserRepo——窄接口签名零变更，
// U8 计划书 1.5「并存至 U10 收敛」兑现）。
type adminLookupAdapter struct{ users storage.UserRepo }

// IsAdminUser 查询管理员身份（用户不存在视为非管理员——防枚举语义保持）。
// 参数：_ 上下文（UserRepo 当前实现同步直查）；name 用户名（已小写）。返回：是否管理员。
func (a adminLookupAdapter) IsAdminUser(ctx context.Context, name string) (bool, error) {
	user, err := a.users.FindByName(ctx, name)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return false, nil
		}
		return false, err
	}
	return user.IsAdmin, nil
}

// dbMessageSource mail.MessageSource 的 DB 适配（messages 行→blob_key→BlobStore.Read，
// 1.5⑥⑧：本域分流原信与 DSN 第三分量共用）。
type dbMessageSource struct {
	db    *sql.DB
	blobs storage.BlobStore
}

// ReadOriginal 按消息主键读原始字节。
func (m *dbMessageSource) ReadOriginal(ctx context.Context, messageID int64) ([]byte, error) {
	var blobKey string
	if err := m.db.QueryRowContext(ctx, `SELECT blob_key FROM messages WHERE id = ?`, messageID).Scan(&blobKey); err != nil {
		return nil, fmt.Errorf("查消息 blob_key: %w", err)
	}
	return m.blobs.Read(ctx, blobKey)
}

// outboundSignerAdapter mail 域签名窄接口的装配适配（nil=未配置——恒 ErrKeyNotConfigured
// 哨兵，走 mail 管道「跳过签名不拒收」路径，U5 计划书步骤 6）。
type outboundSignerAdapter struct {
	inner auth.Signer // U3 契约 2.2 公开接口（nil=未配置）
}

// Sign 未配置返回哨兵；已配置透传。
func (o outboundSignerAdapter) Sign(ctx context.Context, msg []byte, domain string) ([]byte, error) {
	if o.inner == nil {
		return nil, auth.ErrKeyNotConfigured
	}
	return o.inner.Sign(ctx, msg, domain)
}

// credentialVerifierAdapter smtp.CredentialVerifier 的 account.Service 适配
// （U2 签名返回 *storage.Mailbox——窄化丢弃负载仅传错误）。
type credentialVerifierAdapter struct {
	inner func(ctx context.Context, addr, password string) (*storage.Mailbox, error)
}

// VerifyCredentials 凭据校验（错误形态窄化）。
func (c credentialVerifierAdapter) VerifyCredentials(ctx context.Context, addr, password string) error {
	_, err := c.inner(ctx, addr, password)
	return err
}

// daneValidatorAdapter transport.DaneService → mail.DaneValidator 适配（U13——契约
// v1.9.0 2.3：mail 零 transport import，main 桥接做类型转换；RequireDANE 态的握手后
// 认证经 VerifyPeer 闭包捕获完整决策（Records/RefNames）注入——类型细节零泄漏）。
type daneValidatorAdapter struct{ inner *transport.DaneService }

// Check 决策类型转换（三态枚举值序一致——mail/transport 两视图同构声明）。
// 参数：ctx 上下文；mxHost MX 主机名；nextHopDomain 原始下一跳域。
// 返回：mail 视图决策（RequireDANE 态附带 VerifyPeer 闭包）；错误透传。
func (a daneValidatorAdapter) Check(ctx context.Context, mxHost, nextHopDomain string) (*mail.DaneDecision, error) {
	td, err := a.inner.Check(ctx, mxHost, nextHopDomain)
	if err != nil {
		return nil, err
	}
	md := &mail.DaneDecision{Mode: mail.DaneMode(td.Mode), BaseTLSDomain: td.BaseTLSDomain}
	if td.Mode == transport.DaneRequireDANE {
		md.VerifyPeer = func(certs []*x509.Certificate) error {
			return transport.VerifyPeerCertificates(td, certs)
		}
	}
	return md, nil
}

// stsValidatorAdapter transport.STSSenderService → mail.STSValidator 适配（传输安全
// 与日志增强批次 L-A——契约 v1.21.0 2.3：mail 零 transport import，main 桥接类型转换，
// 沿 daneValidatorAdapter 先例）。
type stsValidatorAdapter struct{ inner *transport.STSSenderService }

// Check 决策类型转换（Mode/MXMatched 两字段视图——策略细节零泄漏）。
// 参数：ctx 上下文；policyDomain 收件策略域；mxHost 目标 MX 主机。
// 返回：mail 视图决策；错误透传。
func (a stsValidatorAdapter) Check(ctx context.Context, policyDomain, mxHost string) (*mail.STSDecision, error) {
	td, err := a.inner.Check(ctx, policyDomain, mxHost)
	if err != nil || td == nil {
		return nil, err
	}
	return &mail.STSDecision{Mode: td.Mode, MXMatched: td.MXMatched}, nil
}

// tlsrptRecorderAdapter transport.TLSRPTAggregator → mail.TLSResultRecorder 适配
// （传输安全与日志增强批次 L-B——同上先例）。
type tlsrptRecorderAdapter struct{ inner *transport.TLSRPTAggregator }

// Record 结果采集透传（domain/mxHost/resultType 三参同构）。
func (a tlsrptRecorderAdapter) Record(domain, mxHost, resultType string) {
	a.inner.Record(domain, mxHost, resultType)
}
