// example-plugin 示例插件（TC-016 判定①载体——Q4-A 裁决：同 module 独立 main，
// 共享 proto 生成包与 internal/plugin 桥接类型（Handshake/GRmailPluginGRPC——
// 编译期一致性锚）；构建：make build-plugin（产物 plugins/example-plugin）。
// 能力演示（Q2-A 最小完备集全量）：GetInfo 元信息/OnInbound 收信钩子放行/
// OnSubmit 发信钩子放行/RegisterProtocol 协议声明（宿主登记不路由）。
// 依据：U15 计划书 v1.0.0 1.5⑤（G2 批准 2026-09-24 10:46:55）；FR-016；REQ-023。
// 修改历史：
//
//	2026-09-24 11:05:00 | 新建 | U15 插件系统（计划书步骤 4）
package main

import (
	"context"
	"fmt"
	"os"

	goplugin "github.com/hashicorp/go-plugin"

	"GRmail/internal/plugin"
	pb "GRmail/proto/grmailplugin"
)

// examplePlugin 插件服务端实现（pb.GRmailPluginServer 四方法）。
type examplePlugin struct {
	pb.UnimplementedGRmailPluginServer // 前向兼容：契约后续新增 RPC 不破坏旧插件
}

// GetInfo 元信息（宿主拉起期调用——名称用于日志与监管呈现）。
// 参数：ctx；req 空请求。返回：固定元信息（能力三项全声明）。
func (examplePlugin) GetInfo(_ context.Context, _ *pb.GetInfoRequest) (*pb.PluginInfo, error) {
	return &pb.PluginInfo{
		Name:    "example-plugin",
		Version: "1.0.0",
		Capabilities: []string{
			"inbound_hook", // 收信钩子（FR-005 管道插件链位）
			"submit_hook",  // 发信钩子（DFD P2）
			"protocol",     // 协议注册声明能力（FR-016——宿主登记不路由）
		},
	}, nil
}

// OnInbound 收信钩子（示例：放行+stderr 验证结论回显——经 go-plugin stderr
// 转发进入宿主日志流，演示钩子输入可见性）。
// 参数：ctx；in 收信上下文（信封+四项验证结论+原始字节）。返回：放行决策。
func (examplePlugin) OnInbound(_ context.Context, in *pb.InboundContext) (*pb.HookDecision, error) {
	v := in.GetVerification()
	if v != nil {
		fmt.Fprintf(os.Stderr, "[example-plugin] inbound: spf=%s dkim=%s dmarc=%s arc=%s size=%d\n",
			v.GetSpf(), v.GetDkim(), v.GetDmarc(), v.GetArc(), len(in.GetRawMessage()))
	}
	return &pb.HookDecision{Allow: true}, nil
}

// OnSubmit 发信钩子（示例：放行+提交摘要回显）。
// 参数：ctx；in 提交上下文（信封+认证身份+收件人集+原始字节）。返回：放行决策。
func (examplePlugin) OnSubmit(_ context.Context, in *pb.SubmitContext) (*pb.HookDecision, error) {
	fmt.Fprintf(os.Stderr, "[example-plugin] submit: auth=%s rcpts=%d size=%d\n",
		in.GetAuthUser(), len(in.GetRecipients()), len(in.GetRawMessage()))
	return &pb.HookDecision{Allow: true}, nil
}

// RegisterProtocol 协议注册声明（示例：单条声明 example-proto→收宿主回执→结束）。
// 流向：插件经返回流 Send 声明；宿主登记+日志并经请求流 Send 回执（本期不路由）。
// 参数：stream 双向流（Recv 回执/Send 声明）。返回：流处理错误。
func (examplePlugin) RegisterProtocol(
	stream grpcBidiStream) error {
	if err := stream.Send(&pb.ProtocolRegistration{
		ProtocolName: "example-proto", // 演示协议名（CalDAV/CardDAV 形态预留——FR-017）
		Endpoint:     "/example",
	}); err != nil {
		return err
	}
	ack, err := stream.Recv()
	if err != nil {
		return err // 宿主关闭流（Shutdown 竞态）——非错误态退出
	}
	fmt.Fprintf(os.Stderr, "[example-plugin] protocol registered: accepted=%v note=%s\n",
		ack.GetAccepted(), ack.GetNote())
	return nil
}

// grpcBidiStream 流接口窄别名（服务端侧——Send 声明/Recv 回执）。
type grpcBidiStream = pb.GRmailPlugin_RegisterProtocolServer

func main() {
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: plugin.Handshake, // 与宿主共享编译期锚（internal/plugin）
		Plugins: map[string]goplugin.Plugin{
			plugin.PluginName: &plugin.GRmailPluginGRPC{Impl: examplePlugin{}},
		},
		GRPCServer: goplugin.DefaultGRPCServer, // gRPC 强类型契约（REQ-023）
	})
}
