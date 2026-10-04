// Package observability 追加日志按日切分压缩 Writer（D8#9 收口——传输安全与日志
// 增强批次 L-E；S4-W Q2-A 裁决 2026-10-01 23:05:16 自研最小轮转）。
// 机制：实现 phuslu Writer 接口（WriteEntry(*Entry)）——写侧检测本地日期跨日→持锁
// 切换（旧句柄关闭→旧日期文件异步 gzip 压缩→按保留窗清理超期 .gz→打开新日期文件）；
// 当日内按大小轮转自管承载（超限关闭当前文件、以 .1/.2… 序号续开——防单文件无限
// 膨胀的等价能力，形态与 phuslu 时间戳备份略异，修改文档登记）；日志行零丢失
// （切换失败保留旧句柄继续写+告警）。
// 文件形态：当日=<base去扩展>.<YYYYMMDD>[.N]（app.log → app.20261001[.1]）；切日/关闭
// 归档 gzip=<...>.gz。〔第三版——phuslu FileWriter 内层方案经两轮实证废除：①fileargs
// 强制注入时间戳后缀且 TimeFormat 受控形态仍与扩展位耦合；②内层文件名取真实 UTC
// 墙钟与本包装注入时钟/本地日脱钩（dbg 实证：注入 10-01 落盘 20261002）。自管
// os.File 后文件名/时区/时钟全量受控，可测性回归。〕
// 修改历史：
//
//	2026-10-01 23:20:00 | 新建 | 传输安全与日志增强批次 L-E（计划书步骤 6；
//	G2 批准 2026-10-01 22:54:41；S4-W Q2-A 自研裁决）
//	2026-10-02 00:10:00 | 重构 | 内层 phuslu FileWriter 方案废除——自管 os.File
//	（fileargs 时间戳耦合+内层真实 UTC 墙钟脱钩两实证缺陷收口；当日大小轮转改
//	序号文件自承载）
package observability

import (
	"compress/gzip"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// rotateDayKey 日期切分键格式（本地时区——运维侧按本地日界读日志友好）。
const rotateDayKey = "20060102"

// DailyRotateWriter 按日切分+压缩+保留窗文件 Writer（phuslu Writer 接口实现）。
type DailyRotateWriter struct {
	base       string           // 日志文件基础路径（含扩展——对外口径，如 /var/log/app.log）
	stem       string           // 去扩展基名（当日文件名源）
	maxMB      int              // 当日按大小轮转阈值 MB（0=不按大小）
	backups    int              // 当日轮转序号文件保留份数（0=不限）
	retainDays int              // .gz 保留天数（0=不限）
	now        func() time.Time // 时钟注入（测试跨日驱动）

	mu   sync.Mutex
	day  string   // 当前日期键
	file *os.File // 当日当前文件（append 态；nil=未打开）
	seq  int      // 当日轮转序号（0=主文件；>0=app.<day>.<N>）
	size int64    // 当日当前文件已写字节（大小轮转判定）
}

// NewDailyRotateWriter 构造按日轮转 Writer。
// 参数：base 日志基础路径（当日文件=<stem>.<YYYYMMDD>——如 app.log → app.20261001，
// 大小轮转续 app.20261001.1）；maxMB 当日大小轮转阈值（0=关闭）；backups 序号文件
// 保留份数（0=不限）；retainDays .gz 保留天数（0=不限）。首次写入时惰性打开。
func NewDailyRotateWriter(base string, maxMB, backups, retainDays int) *DailyRotateWriter {
	return &DailyRotateWriter{base: base, stem: splitExt(base), maxMB: maxMB, backups: backups,
		retainDays: retainDays, now: time.Now}
}

// splitExt 拆出去扩展基名（仅最后一段文件名的末个点切分；无点返回原路径）。
func splitExt(path string) (stem string) {
	dir, file := filepath.Split(path)
	if i := strings.LastIndex(file, "."); i > 0 {
		return dir + file[:i]
	}
	return dir + file
}

// dayFile 指定日期（含轮转序号）的文件路径（<stem>.<YYYYMMDD>[.N]）。
func (w *DailyRotateWriter) dayFile(day string, seq int) string {
	if seq > 0 {
		return w.stem + "." + day + "." + itoa(seq)
	}
	return w.stem + "." + day
}

// itoa 十进制串（strconv 薄封装——保持 import 最小）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Write 实现 io.Writer（经 phuslu log.IOWriter 桥接入 Logger.Writer——Entry.buf
// 跨包不可达，IOWriter 在 phuslu 包内取出字节后回调本方法；写前跨日检测+大小轮转检测）。
func (w *DailyRotateWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	day := now.Format(rotateDayKey)
	if w.file == nil || day != w.day {
		if err := w.rotateDayLocked(day); err != nil {
			// 切换失败：保留旧句柄继续写（零丢行优先——可靠性高于切分）
			if w.file != nil {
				slog.Default().Warn("日志按日切分失败，继续写入当前文件", "error", err, "day", day)
				return w.file.Write(p)
			}
			return 0, err
		}
	}
	// 当日大小轮转：超阈值关当前→序号续开（压缩归档仍以日为粒度——切日时全量 gzip）
	if w.maxMB > 0 && w.size+int64(len(p)) > int64(w.maxMB)*1024*1024 {
		if err := w.rotateSizeLocked(day); err != nil {
			slog.Default().Warn("日志大小轮转失败，继续写入当前文件", "error", err)
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// Close 关闭当日文件（优雅退出/热重建时释放句柄；当日全序列 gzip 归档）。
func (w *DailyRotateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeLocked()
}

// closeLocked 关闭并归档（持锁路径）。
func (w *DailyRotateWriter) closeLocked() error {
	if w.file == nil {
		return nil
	}
	day, seq := w.day, w.seq
	err := w.file.Close()
	w.file = nil
	if err == nil && day != "" {
		go w.archiveDay(day, seq) // 当日全部序号文件压缩归档（尽力）
	}
	return err
}

// rotateDayLocked 切换到新日期主文件（持锁调用方：w.mu）。
func (w *DailyRotateWriter) rotateDayLocked(newDay string) error {
	oldDay, oldSeq := w.day, w.seq
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return err // 关闭失败中止切换（上层兜底保旧句柄）
		}
		w.file = nil
		if oldDay != "" {
			go w.archiveDay(oldDay, oldSeq) // 旧日全序列异步压缩（不阻塞写路径）
		}
	}
	if w.retainDays > 0 {
		go w.purgeExpired() // 异步清理（尽力）
	}
	f, size, err := openAppend(w.dayFile(newDay, 0))
	if err != nil {
		return err
	}
	w.file, w.day, w.seq, w.size = f, newDay, 0, size
	return nil
}

// rotateSizeLocked 当日大小轮转（持锁调用方：w.mu；失败时上层继续写旧句柄）。
func (w *DailyRotateWriter) rotateSizeLocked(day string) error {
	if err := w.file.Close(); err != nil {
		return err
	}
	next := w.seq + 1
	f, _, err := openAppend(w.dayFile(day, next))
	if err != nil {
		return err
	}
	w.file, w.seq, w.size = f, next, 0
	return nil
}

// openAppend 打开（或创建）文件为追加态；返回句柄与当前大小。
func openAppend(path string) (*os.File, int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, 0, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// archiveDay 压缩归档指定日期全部文件（主+序号——序号倒序gzip；尽力语义）。
func (w *DailyRotateWriter) archiveDay(day string, topSeq int) {
	for seq := topSeq; seq >= 0; seq-- {
		compressLogFile(w.dayFile(day, seq))
	}
}

// purgeExpired 清理保留窗外 .gz 归档（文件名日期判定——<stem>.<YYYYMMDD>*.gz）。
func (w *DailyRotateWriter) purgeExpired() {
	matches, err := filepath.Glob(w.stem + ".*.gz")
	if err != nil {
		return
	}
	cutoff := w.now().AddDate(0, 0, -w.retainDays).Format(rotateDayKey)
	baseStem := filepath.Base(w.stem) + "."
	for _, m := range matches {
		name := strings.TrimPrefix(filepath.Base(m), baseStem) // <YYYYMMDD>[.N].gz
		day := name
		if i := strings.Index(name, "."); i == len(rotateDayKey) {
			day = name[:i]
		}
		day = strings.TrimSuffix(day, ".gz")
		if len(day) == len(rotateDayKey) && day < cutoff {
			if rmErr := os.Remove(m); rmErr == nil {
				slog.Default().Info("日志归档超保留窗清理", "file", m, "retainDays", w.retainDays)
			}
		}
	}
}

// compressLogFile 单文件 gzip 压缩（src→src+".gz"，成功后删源；尽力语义——
// 失败告警保留源文件，下轮退出不重试〔切分唯一时机〕，运维侧可手动压缩）。
func compressLogFile(src string) {
	in, err := os.Open(src)
	if err != nil {
		return // 源不存在（当日空文件未建）——静默
	}
	tmp := src + ".gz.tmp"
	out, err := os.Create(tmp)
	if err != nil {
		_ = in.Close()
		slog.Default().Warn("日志压缩创建失败（保留源文件）", "file", src, "error", err)
		return
	}
	gz := gzip.NewWriter(out)
	if _, err = io.Copy(gz, in); err == nil {
		err = gz.Close()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if ierr := in.Close(); err == nil {
		err = ierr
	}
	if err != nil {
		_ = os.Remove(tmp)
		slog.Default().Warn("日志压缩写入失败（保留源文件）", "file", src, "error", err)
		return
	}
	if err = os.Rename(tmp, src+".gz"); err != nil {
		_ = os.Remove(tmp)
		slog.Default().Warn("日志压缩落名失败（保留源文件）", "file", src, "error", err)
		return
	}
	_ = os.Remove(src) // .gz 落定后删源（成功路径最后一步）
}
