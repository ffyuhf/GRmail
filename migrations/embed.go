// Package migrations 内嵌三库迁移脚本（embed 路径以本包目录为基准）。
// 依据：Q5（goose 版本化迁移）、数据库表结构 v1.0.0 第五章（三库分目录、同版本号同语义）。
// 修改历史：
//
//	2026-09-16 04:40:00 | 新建 | U1 工程骨架（修正 embed 基准目录问题）
package migrations

import "embed"

// SQLite 方言迁移脚本（内置默认库）
//
//go:embed sqlite/*.sql
var SQLite embed.FS

// MySQL 方言迁移脚本
//
//go:embed mysql/*.sql
var MySQL embed.FS

// PostgreSQL 方言迁移脚本
//
//go:embed postgres/*.sql
var Postgres embed.FS
