// killProcess 平台辅助：向插件子进程发送 SIGKILL（崩溃隔离测试用——TC-016 判定②）。
// 限 unix（Windows 经 TC-026 构建矩阵覆盖，测试用例侧已 //go:build !windows 隔离）。
// 修改历史：
//
//	2026-09-24 11:10:00 | 新建 | U15 插件系统（计划书步骤 6——崩溃隔离用例辅助）
//
//go:build !windows

package plugin

import "syscall"

// killProcess 向指定进程发送 SIGKILL（测试注入崩溃）。
// 参数：pid 目标进程。返回：信号发送错误。
func killProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
