// GRmail 邮件服务器模块定义
// 修改历史：
//   2026-09-16 04:32:00 | 新建 | U1 工程骨架（Q14 裁决：module=GRmail，modernc.org/sqlite）
//   2026-09-16 04:47:00 | 基线确认 | go 1.26 基线经干系人 T1-A 裁决生效（goose v3.28.0 要求 ≥1.26）
module GRmail

go 1.26.0

require (
	github.com/a-h/templ v0.3.1020
	github.com/emersion/go-imap/v2 v2.0.0-beta.8
	github.com/emersion/go-message v0.18.2
	github.com/fsnotify/fsnotify v1.10.1
	github.com/gin-gonic/gin v1.12.0
	github.com/go-acme/lego/v4 v4.35.2
	github.com/go-sql-driver/mysql v1.10.1
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/go-plugin v1.8.0
	github.com/jackc/pgx/v5 v5.11.0
	github.com/miekg/dns v1.1.73
	github.com/phuslu/log v1.0.133
	github.com/pressly/goose/v3 v3.28.0
	github.com/stephenafamo/bob v0.50.0
	github.com/synqronlabs/raven v1.6.1
	github.com/veqryn/slog-context v0.9.0
	golang.org/x/crypto v0.55.0
	golang.org/x/text v0.42.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
	modernc.org/sqlite v1.59.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/aarondl/opt v0.0.0-20250607033636-982744e1bd65 // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/creachadair/otp v0.5.5 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.1 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/gofrs/uuid/v5 v5.4.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/json-iterator/go v1.1.13-0.20220915233716-71ac16282d12 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pschlump/ansi v1.0.6 // indirect
	github.com/pschlump/dbgo v1.0.8 // indirect
	github.com/pschlump/filelib v1.0.12 // indirect
	github.com/pschlump/go-colorable v0.0.23 // indirect
	github.com/pschlump/go-isatty v0.0.23 // indirect
	github.com/pschlump/goqrcode v1.1.0 // indirect
	github.com/pschlump/json v1.12.1 // indirect
	github.com/qdm12/reprint v0.0.0-20200326205758-722754a53494 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/sethvargo/go-retry v0.4.0 // indirect
	github.com/stephenafamo/scan v0.9.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	go.mongodb.org/mongo-driver/v2 v2.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/arch v0.22.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260831171406-18b4a7587f8a // indirect
	modernc.org/libc v1.75.7 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
