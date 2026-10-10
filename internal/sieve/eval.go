// sieve 求值器：rfc5228 §2.10 求值语义 + §3 控制 + §4 四动作 + §5 十测试 + rfc5232
// imap4flags（R1-A 自研）；Runner 实现 grmail.SieveRunner（契约 v1.8.0 2.3——依赖方向
// sieve→mail 合法，架构第四章单向链；动作执行归 mail 域——本包零存储/网络 IO，NFR-015）。
// 规范锚点：§2.10.2 implicit keep（fileinto/keep/redirect/discard 取消；策略忽略的
// redirect 不取消）；§2.10.3 同邮箱重复投递 SHOULD NOT（fileinto 同名合并由 target
// 归一承载）；§2.10.6 错误即停+通知+implicit keep 兜底；§3.3 stop（未取消则保留）；
// §4.1 fileinto（不存在 MAY error——取错误分支交管道兜底）；§4.2 redirect（数量上限
// MUST+环控 MUST——Received 计数）；§4.4 discard（静默，兼容其他动作）；rfc5232 §2/§3
// （标志校验失败忽略、\Recent 等不可设系统标志 MUST 忽略；内部变量空集起）。
// 修改历史：
//
//	2026-09-21 00:54:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 6/7）
//	2026-09-29 17:17:00 | 修正 | RFC候选修正批次 RF-F：F-S1 header/address/envelope 双列表求值+fileinto :flags 参数序+decode 链超范围错误上抛（F-S21）
//	2026-10-08 10:20:00 | 优化 | 性能批 F5（B-P4，G2 批准 2026-10-08 10:13:49）：编译缓存
//	  ——脚本内容 SHA-256 键→AST（原每封来信全流程 Parse 重复编译消除；内容变更
//	  天然失效；条目上限随机淘汰防无界增长；求值纯函数语义零变化——rfc5228 §2.10.6
//	  错误即停行为保持）
//	2026-10-10 16:05:00 | 优化 | C级债务收尾批（G2 批准 2026-10-10 15:45:40）：
//	  F8/C19② header 测试头值 rfc2047 encoded-word 解码（rfc5228 §2.4.2.2「SHOULD
//	  be done according to [MIME3]」+§5.7 首尾空白忽略——mime.WordDecoder，失败
//	  原样宽容）+F18③/C19③ address 测试限定地址结构头白名单（§5.1「MUST restrict
//	  to headers that contain addresses」——From/To/Cc/Bcc/Sender/Resent-From/
//	  Resent-To 最小履行集）
package sieve

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"mime"
	stdmail "net/mail"
	"strings"
	"sync"

	grmail "GRmail/internal/mail"
	"GRmail/internal/storage"
)

// sieveCacheMax 编译缓存条目上限（性能批 F5——超限随机淘汰一项：map 迭代序随机，
// 简单淘汰不追求 LRU 精度；条目为 AST 指针轻量，单管理员自托管场景远达不到上限）。
const sieveCacheMax = 256

// Runner Sieve 执行器（grmail.SieveRunner 实现——管道经 SetSieveRunner 注入）。
type Runner struct {
	scripts storage.SieveScriptRepo

	// astCache 编译缓存（F5/B-P4）：脚本内容 SHA-256 → 解析产物。同一邮箱激活脚本
	// 固定，原每封来信重新 Parse（词法+递归下降）重复编译；缓存后内容变更天然失效
	// （哈希键不同即新条目——PUTSCRIPT/DELETE 零联动成本）。AST 为只读消费
	// （evalScript 纯函数零改写），并发共享安全。
	cacheMu  sync.Mutex
	astCache map[[sha256.Size]byte]*Script
}

// NewRunner 构造执行器。
// 参数：scripts Sieve 脚本仓储（GetActiveScript 逐收件人查询）。
func NewRunner(scripts storage.SieveScriptRepo) *Runner {
	return &Runner{scripts: scripts, astCache: make(map[[sha256.Size]byte]*Script)}
}

// 编译期断言：契约 v1.8.0 2.3 接口实现锁定。
var _ grmail.SieveRunner = (*Runner)(nil)

// RunForMailbox 对单收件邮箱执行激活脚本（契约 v1.8.0）。
// 无激活脚本返回 (nil, nil)（管道按直达 INBOX 原语义处理）。
func (r *Runner) RunForMailbox(ctx context.Context, mailboxID int64, evalCtx *grmail.EvalContext) (*grmail.SieveDelivery, error) {
	script, err := r.scripts.GetActiveScript(ctx, mailboxID)
	if err != nil {
		if errors.Is(err, storage.ErrNoActiveScript) {
			return nil, nil
		}
		return nil, fmt.Errorf("查询激活脚本: %w", err)
	}
	ast, err := r.parseCached(script.Content)
	if err != nil {
		// 运行期出现编译期错误（保存校验遗漏/并发改写窗口）——按运行时错误同径兜底
		return nil, fmt.Errorf("激活脚本解析失败: %w", err)
	}
	return evalScript(ast, evalCtx)
}

// parseCached 带缓存的脚本解析（F5/B-P4）。
// 语义：同内容命中缓存直接返回 AST 指针（解析零开销）；未命中执行全流程 Parse 后
// 入缓存；解析失败不入缓存（每次重试——错误即停语义保持，rfc5228 §2.10.6）。
// 参数：content 脚本源文本。返回：解析产物（缓存共享只读）；解析失败原因。
func (r *Runner) parseCached(content string) (*Script, error) {
	sum := sha256.Sum256([]byte(content))
	r.cacheMu.Lock()
	ast, ok := r.astCache[sum]
	r.cacheMu.Unlock()
	if ok {
		return ast, nil
	}
	ast, err := Parse(content)
	if err != nil {
		return nil, err
	}
	r.cacheMu.Lock()
	if len(r.astCache) >= sieveCacheMax {
		for k := range r.astCache { // 随机淘汰一项（map 迭代序随机）
			delete(r.astCache, k)
			break
		}
	}
	r.astCache[sum] = ast
	r.cacheMu.Unlock()
	return ast, nil
}

// evalState 求值状态（implicit keep 状态机载体）。
type evalState struct {
	cancelKeep    bool            // implicit keep 已取消（四动作任一执行）
	discarded     bool            // discard 已执行（无投递动作时=静默丢弃）
	fileInto      string          // fileinto 目标（keep 不改目标——INBOX 语义）
	redirects     []string        // redirect 目标集（上限校验即时执行）
	flagSeen      bool            // 最终投递行 \Seen 初值（内部变量或 :flags）
	flagFlagged   bool            // 最终投递行 \Flagged 初值
	internalFlags map[string]bool // rfc5232 内部变量（无 variables 形态——空集起 §3）
	stopped       bool            // stop 已执行
	decodeEnc     bool            // encoded-character 解码开关（require 声明态）
}

// evalScript 脚本求值主入口（纯函数——NFR-015）。
func evalScript(ast *Script, evalCtx *grmail.EvalContext) (*grmail.SieveDelivery, error) {
	st := &evalState{internalFlags: map[string]bool{}, decodeEnc: ast.Requires["encoded-character"]}
	if err := st.execCommands(ast.Commands, evalCtx); err != nil {
		return nil, err // 运行时错误——调用方 implicit keep 兜底（§2.10.6）
	}
	dlv := &grmail.SieveDelivery{
		FlagSeen:    st.flagSeen,
		FlagFlagged: st.flagFlagged,
	}
	switch {
	case st.discarded && st.fileInto == "" && len(st.redirects) == 0:
		dlv.Discard = true // 纯 discard：静默丢弃（§4.4）
		return dlv, nil
	case st.cancelKeep:
		dlv.FileInto = st.fileInto
		dlv.Redirects = st.redirects
		return dlv, nil
	default:
		// implicit keep（未取消——含空脚本/条件未命中/stop 未取消）：INBOX+内部 flags
		dlv.FlagSeen = st.internalFlags["\\seen"]
		dlv.FlagFlagged = st.internalFlags["\\flagged"]
		return dlv, nil
	}
}

// execCommands 命令序列执行（含 if/elsif/else 链状态机——扁平序列形态 §3.1）。
func (st *evalState) execCommands(cmds []CommandNode, evalCtx *grmail.EvalContext) error {
	chainTaken := false // 当前链已有分支命中
	inChain := false    // 是否处于 if 链中
	for _, c := range cmds {
		if st.stopped {
			return nil
		}
		switch c.Name {
		case "if":
			hit, err := st.evalTest(c.Test, evalCtx)
			if err != nil {
				return err
			}
			inChain, chainTaken = true, hit
			if hit {
				if err = st.execCommands(c.Block, evalCtx); err != nil {
					return err
				}
			}
		case "elsif":
			if !inChain {
				return syntaxErr(c.Line, "elsif 未链随 if（解析器已拦截——防御态）")
			}
			if chainTaken {
				continue
			}
			hit, err := st.evalTest(c.Test, evalCtx)
			if err != nil {
				return err
			}
			if hit {
				chainTaken = true
				if err = st.execCommands(c.Block, evalCtx); err != nil {
					return err
				}
			}
		case "else":
			if !inChain {
				return syntaxErr(c.Line, "else 未链随 if（解析器已拦截——防御态）")
			}
			if !chainTaken {
				if err := st.execCommands(c.Block, evalCtx); err != nil {
					return err
				}
			}
			inChain = false // 链结束
		case "stop":
			st.stopped = true // §3.3：未取消 implicit keep 则保留——状态不动作
			return nil
		case "keep":
			// §4.3：默认投递（INBOX——fileInto 保持现值）；flags 应用内部变量缺省
			st.cancelKeep = true
			st.flagSeen = st.internalFlags["\\seen"]
			st.flagFlagged = st.internalFlags["\\flagged"]
		case "fileinto":
			// §4.1：目标文件夹；:flags 显式列表优先（rfc5232 §3——参数序
			// [flags..., mailbox]，邮箱名为末元素——RF-F/F-S14 与 parser 形态对齐）
			st.cancelKeep = true
			if len(c.Tags) > 0 {
				mbox, derr := st.decode(c.Strings[len(c.Strings)-1])
				if derr != nil {
					return derr
				}
				st.fileInto = mbox
				st.flagSeen, st.flagFlagged = st.flagsSeenFlagged(c.Strings[:len(c.Strings)-1])
			} else {
				mbox, derr := st.decode(c.Strings[0])
				if derr != nil {
					return derr
				}
				st.fileInto = mbox
				// 缺省用内部变量当前值（rfc5232 §3 L183-187：
				// "the current value of the internal variable is used instead"）
				st.flagSeen, st.flagFlagged = st.internalFlags["\\seen"], st.internalFlags["\\flagged"]
			}
		case "redirect":
			// §4.2：环控（Received 计数上限）+数量上限 MUST；入列（不取消态由
			// cancelKeep 统一标记——redirect 取消 implicit keep）
			if evalCtx.ReceivedCount >= grmail.MaxReceivedHopCount {
				return fmt.Errorf("redirect 环控拒绝：Received 计数 %d ≥ 上限 %d（rfc5228 §4.2）",
					evalCtx.ReceivedCount, grmail.MaxReceivedHopCount)
			}
			if len(st.redirects)+1 > grmail.MaxRedirects {
				return fmt.Errorf("redirect 数量超上限 %d（rfc5228 §4.2 MUST）", grmail.MaxRedirects)
			}
			st.cancelKeep = true
			addr, derr := st.decode(c.Strings[0])
			if derr != nil {
				return derr
			}
			st.redirects = append(st.redirects, addr)
		case "discard":
			// §4.4：静默（不产生任何通知）；兼容其他动作（fileinto+discard=fileinto）
			st.cancelKeep = true
			st.discarded = true
		case "setflag":
			st.setFlags(c.Strings, true, true)
		case "addflag":
			st.setFlags(c.Strings, false, true)
		case "removeflag":
			st.setFlags(c.Strings, false, false)
		default:
			return syntaxErr(c.Line, "未知命令 %q（求值期——解析器漏拦防御态）", c.Name)
		}
	}
	return nil
}

// evalTest 测试求值（§5 全集+rfc5232 hasflag）。
func (st *evalState) evalTest(t *TestNode, evalCtx *grmail.EvalContext) (bool, error) {
	switch t.Name {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "not":
		v, err := st.evalTest(t.Tests[0], evalCtx)
		return !v, err
	case "allof":
		for _, sub := range t.Tests {
			v, err := st.evalTest(sub, evalCtx)
			if err != nil {
				return false, err
			}
			if !v {
				return false, nil
			}
		}
		return true, nil
	case "anyof":
		for _, sub := range t.Tests {
			v, err := st.evalTest(sub, evalCtx)
			if err != nil {
				return false, err
			}
			if v {
				return true, nil
			}
		}
		return false, nil
	case "exists":
		for _, h := range t.Strings {
			if len(evalCtx.Headers[strings.ToLower(h)]) == 0 {
				return false, nil
			}
		}
		return true, nil
	case "size":
		_, _, _, dir, _ := tagsOf(t.Tags)
		limit := *t.Number
		if dir == "over" {
			return evalCtx.RawSize > limit, nil // §5.9：恰等于既非 over 亦非 under
		}
		return evalCtx.RawSize < limit, nil
	case "header":
		matchType, comparator, _, _, _ := tagsOf(t.Tags)
		comp, ok := resolveComparator(comparator)
		if !ok {
			return false, syntaxErr(t.Line, "未知比较器 %q（rfc5228 §2.7.3）", comparator)
		}
		// RF-F/F-S1：names/keys 双列表全量承载（§5.7「the value of any of the
		// named headers ... matches any key」——任一 named 头值×任一 key 命中即真）。
		// F8/C19②：头值比较前 rfc2047 解码+首尾空白忽略（§2.4.2.2+§5.7）。
		var values []string
		for _, n := range t.Names {
			for _, hv := range evalCtx.Headers[strings.ToLower(n)] {
				values = append(values, decodeHeaderValue(hv))
			}
		}
		keys, kerr := st.decodeAll(t.Keys)
		if kerr != nil {
			return false, kerr
		}
		return matchAny(comp, matchType, values, keys), nil
	case "address", "envelope":
		matchType, comparator, addrPart, _, _ := tagsOf(t.Tags)
		comp, ok := resolveComparator(comparator)
		if !ok {
			return false, syntaxErr(t.Line, "未知比较器 %q（rfc5228 §2.7.3）", comparator)
		}
		// RF-F/F-S1：parts/keys 双列表边界承载（§5.1/§5.4——Names=前段、Keys=后段；
		// 两列表非空已由 parser 校验）
		parts := t.Names
		keys, kerr := st.decodeAll(t.Keys)
		if kerr != nil {
			return false, kerr
		}
		var values []string
		if t.Name == "envelope" {
			for _, p := range parts {
				switch strings.ToLower(p) {
				case "from": // §5.4：null reverse-path 匹配空串（ADDRESS-PART 无关）
					if evalCtx.Envelope.MailFrom == "" {
						values = append(values, "")
					} else {
						values = append(values, addressPart(evalCtx.Envelope.MailFrom, addrPart))
					}
				case "to": // 导致投递给该用户的 RCPT（最近且唯一）
					values = append(values, addressPart(evalCtx.Recipient, addrPart))
				default:
					return false, syntaxErr(t.Line, "未知 envelope 部分 %q（§5.4 SHOULD error）", p)
				}
			}
		} else {
			// F18③/C19③（2026-10-10 C级债务收尾批）：§5.1「Implementations MUST
			// restrict the address test to headers that contain addresses」——
			// 白名单限定（From/To/Cc/Bcc/Sender/Resent-From/Resent-To 最小履行集；
			// 白名单外头名=运行时错误即停+implicit keep 兜底，与未知 envelope 部分
			// 同款处置）。
			for _, p := range parts {
				if !isAddressHeader(p) {
					return false, syntaxErr(t.Line, "address 测试仅限地址结构头（rfc5228 §5.1 MUST restrict）: %q", p)
				}
				for _, hv := range evalCtx.Headers[strings.ToLower(p)] {
					// F8 同源：phrase 内 encoded-word 解码（rfc2047 §5(3)）后地址提取
					values = append(values, extractAddresses(decodeHeaderValue(hv), addrPart)...) // §5.1：结构化头逐地址
				}
			}
		}
		return matchAny(comp, matchType, values, keys), nil
	case "hasflag":
		// rfc5232 §4：内部变量（无变量列表形态）；默认 :is+i;ascii-casemap
		matchType, comparator, _, _, _ := tagsOf(t.Tags)
		comp, ok := resolveComparator(comparator)
		if !ok {
			return false, syntaxErr(t.Line, "未知比较器 %q", comparator)
		}
		var values []string
		for f := range st.internalFlags {
			values = append(values, f)
		}
		keys, kerr := st.decodeAll(t.Strings)
		if kerr != nil {
			return false, kerr
		}
		return matchAny(comp, matchType, values, keys), nil
	default:
		return false, syntaxErr(t.Line, "未知测试 %q（求值期防御态）", t.Name)
	}
}

// addressHeaders 地址结构头白名单（F18③/C19③——rfc5228 §5.1 MUST restrict 的最小
// 履行集：From/To/Cc/Bcc/Sender/Resent-From/Resent-To；键小写归一）。
var addressHeaders = map[string]bool{
	"from": true, "to": true, "cc": true, "bcc": true,
	"sender": true, "resent-from": true, "resent-to": true,
}

// isAddressHeader 地址结构头判定（大小写不敏感）。
func isAddressHeader(name string) bool { return addressHeaders[strings.ToLower(name)] }

// decodeHeaderValue 头值比较前解码（F8/C19②——rfc5228 §2.4.2.2「Interpretation of
// header data SHOULD be done according to [MIME3] section 6.2」+§2.7.2 跨字符集
// 比较转 UTF-8+§5.7「ignoring leading and trailing whitespace」）：mime.WordDecoder
// 解码 rfc2047 encoded-word（B/Q 双编码；默认 charset 集覆盖 §2.7.2 MUST 的
// US-ASCII/ISO-8859-1/UTF-8）+首尾空白忽略；解码失败原样（§2.7.2「MAY be treated
// as plain US-ASCII」宽容口径）。
func decodeHeaderValue(v string) string {
	dec, err := (&mime.WordDecoder{}).DecodeHeader(v)
	if err != nil {
		dec = v
	}
	return strings.TrimSpace(dec)
}

// extractAddresses 头值提取地址分量（§5.1：仅地址结构头——From/To/Cc/Bcc/Sender/
// Resent-*；解析失败地址不参与 :localpart/:domain 匹配；phrase/group 不参与）。
func extractAddresses(headerValue, addrPart string) []string {
	list, err := stdmail.ParseAddressList(headerValue)
	if err != nil {
		return nil // 畸形头→无有效地址（不匹配——§5.1 invalid 口径）
	}
	var out []string
	for _, a := range list {
		if a.Address != "" {
			out = append(out, addressPart(a.Address, addrPart))
		}
	}
	return out
}

// addressPart 地址分量提取（§2.7.4：:all 缺省/:localpart/:domain）。
func addressPart(addr, part string) string {
	if part == "localpart" {
		if i := strings.LastIndexByte(addr, '@'); i > 0 {
			return addr[:i]
		}
		return "" // 无域部分的非语法地址——:localpart/:domain 不匹配（§2.7.4 L903）
	}
	if part == "domain" {
		if i := strings.LastIndexByte(addr, '@'); i >= 0 && i+1 < len(addr) {
			return addr[i+1:]
		}
		return ""
	}
	return addr // :all（缺省）
}

// setFlags rfc5232 标志变量操作（§2 校验：非法标志忽略；\Recent 等不可设系统标志
// MUST 忽略；大小写不敏感归一）。
func (st *evalState) setFlags(args []string, replace, add bool) {
	valid := make([]string, 0, len(args))
	for _, f := range args {
		lf := strings.ToLower(f)
		if lf == "\\recent" || lf == "" { // \Recent 不可设（§2）；空串忽略（§2 MUST）
			continue
		}
		if strings.ContainsAny(lf, " \t") { // 空格分隔多标志（§2 等价拆分）
			valid = append(valid, strings.Fields(lf)...)
			continue
		}
		valid = append(valid, lf)
	}
	if replace {
		st.internalFlags = map[string]bool{}
	}
	for _, f := range valid {
		f = strings.ToLower(f)
		if f == "\\recent" {
			continue
		}
		if add {
			st.internalFlags[f] = true
		} else {
			delete(st.internalFlags, f)
		}
	}
}

// flagsSeenFlagged 显式 :flags 列表→投递初值（rfc5232 §3——\Seen/\Flagged 持久承载列）。
func (st *evalState) flagsSeenFlagged(list []string) (bool, bool) {
	seen, flagged := false, false
	for _, f := range list {
		switch strings.ToLower(f) {
		case "\\seen":
			seen = true
		case "\\flagged":
			flagged = true
		}
	}
	return seen, flagged
}

// decode encoded-character 条件解码（§2.4.2.4——require 声明态生效；未声明原样）。
// RF-F/F-S21：解码遇语法合式但超范围的 unicode 值时上抛错误（rfc5228 L567-569
// 「It is an error for a script to use a hexadecimal value that isn't in either
// the range 0 to D7FF or the range E000 to 10FFFF」——错误即停语义 §2.10.6）。
func (st *evalState) decode(s string) (string, error) {
	if !st.decodeEnc {
		return s, nil
	}
	return decodeEncodedChars(s)
}

// decodeAll 列表批量解码（错误同 decode 上抛）。
func (st *evalState) decodeAll(list []string) ([]string, error) {
	if !st.decodeEnc {
		return list, nil
	}
	out := make([]string, len(list))
	for i, s := range list {
		v, err := decodeEncodedChars(s)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// decodeEncodedChars ${hex:}/${unicode:} 解码（§2.4.2.4 语法：hex-pair 1-2 位、
// 空白分隔序列、大小写不介意关键字；语法不符原样保留——L587-603 示例口径；
// RF-F/F-S21：语法合式但超范围（>10FFFF 或 D800-DFFF）按规范报错上抛）。
func decodeEncodedChars(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) || s[i+1] != '{' {
			b.WriteByte(s[i])
			continue
		}
		close := strings.IndexByte(s[i:], '}')
		if close < 0 {
			b.WriteString(s[i:])
			return b.String(), nil
		}
		inner := s[i+2 : i+close]
		var decoded []byte
		ok := true
		rangeErr := false
		switch {
		case strings.HasPrefix(strings.ToLower(inner), "hex:"):
			ok = decodeHexPairs(inner[4:], &decoded)
		case strings.HasPrefix(strings.ToLower(inner), "unicode:"):
			ok, rangeErr = decodeUnicodeSeq(inner[8:], &decoded)
		default:
			ok = false
		}
		if rangeErr {
			return "", fmt.Errorf("encoded-character 超范围（rfc5228 §2.4.2.4——合法区间 0-D7FF/E000-10FFFF）: %q", s[i:i+close+1])
		}
		if !ok {
			// 语法不符（${hex:40 未闭合形态等）——原样保留（L593 示例）
			b.WriteString(s[i : i+close+1])
		} else {
			b.Write(decoded)
		}
		i += close
	}
	return b.String(), nil
}

// decodeHexPairs hex 序列解码（hex-pair 1-2 位、空白分隔——L541-544 文法）。
func decodeHexPairs(seq string, out *[]byte) bool {
	fields := strings.Fields(seq)
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if len(f) < 1 || len(f) > 2 {
			return false
		}
		v := 0
		for j := 0; j < len(f); j++ {
			c := f[j]
			var d int
			switch {
			case c >= '0' && c <= '9':
				d = int(c - '0')
			case c >= 'a' && c <= 'f':
				d = int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				d = int(c-'A') + 10
			default:
				return false
			}
			v = v*16 + d
		}
		*out = append(*out, byte(v))
	}
	return true
}

// decodeUnicodeSeq unicode 序列解码（UTF-8 编码产出）。
// RF-F/F-S21：返回双布尔——ok=false 且 rangeErr=true 为语法合式但超范围
// （L567-571 错误口径——调用方上抛）；ok=false 且 rangeErr=false 为语法不符
// （原样保留口径 L593 示例）。
func decodeUnicodeSeq(seq string, out *[]byte) (ok, rangeErr bool) {
	fields := strings.Fields(seq)
	if len(fields) == 0 {
		return false, false
	}
	runes := make([]rune, 0, len(fields))
	for _, f := range fields {
		var v rune
		for j := 0; j < len(f); j++ {
			c := f[j]
			var d rune
			switch {
			case c >= '0' && c <= '9':
				d = rune(c - '0')
			case c >= 'a' && c <= 'f':
				d = rune(c-'a') + 10
			case c >= 'A' && c <= 'F':
				d = rune(c-'A') + 10
			default:
				return false, false
			}
			v = v*16 + d
		}
		if (v >= 0xD800 && v <= 0xDFFF) || v > 0x10FFFF {
			return false, true // 超范围——规范错误（L567-571）
		}
		runes = append(runes, v)
	}
	for _, r := range runes {
		*out = append(*out, []byte(string(r))...)
	}
	return true, false
}
