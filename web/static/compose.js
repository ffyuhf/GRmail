/* GRmail 写信页脚本（B-S批 F2——内联外迁：迁自 compose.templ 内联脚本块
 * 〔U17 富文本/U16 CSV/U22 图片压缩/E-A 快捷键/E-B 表格——逻辑零变化〕+
 * 内联事件改绑定〔csv 解析/全屏/form 提交桥接/CSV 合入委托——CSP script-src
 * 'self' 配套，本文件即原内联位置的 quill.js 后局部加载〕）。
 * 依据：B-S安全域批_计划_20261009_13-36-00_v2.0.0 1.2-F2（裁决 A 2026-10-09 13:34）。 */
(function () {
	"use strict";

	var grmailEditor = null;
	// U22 图片压缩工程常量（计划书 1.5③——实现级常量非 config 承载：
	// 最长边重采样上限/JPEG 质量档——D8#11：config 注入（compose-page
	// data-* 承载——改 config.json 热加载后下次渲染生效；缺省兜底 1920/0.85）
	var GRMAIL_IMG_MAX_EDGE = parseInt(document.getElementById('compose-page').dataset.imgMaxEdge) || 1920;
	var GRMAIL_JPEG_QUALITY = parseFloat(document.getElementById('compose-page').dataset.jpegQuality) || 0.85;

	// 初始化：snow 主题+自定义 toolbar 容器（模板渲染双语 title）；
	// 初始内容经隐藏 textarea 携带（HTML 源文本）——dangerouslyPasteHTML
	// 注入（自产内容：草稿回填/回信预填，接收侧 iframe sandbox 既有防线）。
	function grmailEditorInit() {
		if (typeof Quill === 'undefined') { return; }
		grmailEditor = new Quill('#editor-container', {
			theme: 'snow',
			modules: {
				toolbar: {
					container: '#compose-toolbar',
					handlers: {
						// U22：undo/redo 无 toolbar 内置按钮（源码核对
						// 零 ql-undo/ql-redo 注册）——经 history 模块
						// （内置）两行桥接
						undo: function () { this.quill.history.undo(); },
						redo: function () { this.quill.history.redo(); },
						// E-B（D8#13）：表格插入——Quill 2.0.3 内置 table
						// 模块（insertTable/行操作 API——vendor 源码实证）
						// 工具栏化激活：固定 2×2 起步（计划书 2.3-2 候选 A
						// 最小面自决；单元格编辑经 contenteditable 既有承载）
						table: function () { this.quill.getModule('table').insertTable(2, 2); }
					}
				},
				// E-B：table 模块显式启用（snow 主题下幂等——注册形态
				// 与 vendor 内置一致，显式声明消除主题默认差异）
				table: true,
				// U22 图片统一压缩接线（源码核对：工具栏选择/粘贴 files/
				// 拖放三路径全部汇聚 uploader.upload→options.handler——
				// 一处覆盖全入口；mimetypes 扩展 png/jpeg/gif/webp 与
				// image/* 等价，svg 排除——data: 内联脚本面收敛）
				uploader: {
					mimetypes: ['image/png', 'image/jpeg', 'image/gif', 'image/webp'],
					handler: grmailUploaderHandler
				}
			}
		});
		var initial = document.getElementById('editor-initial').value;
		if (initial && initial.trim() !== '') {
			grmailEditor.clipboard.dangerouslyPasteHTML(initial);
		}
	}

	// Blob/File → data: URL（FileReader 原语——压缩输出与原样兜底共用）。
	function grmailReadAsDataURL(blob) {
		return new Promise(function (resolve) {
			var reader = new FileReader();
			reader.onload = function () { resolve(reader.result); };
			reader.onerror = function () { resolve(''); };
			reader.readAsDataURL(blob);
		});
	}

	// U22 图片压缩纯函数（Canvas 最长边重采样——缓解 base64 膨胀收口 U19
	// 登记项③）：①非 image/* 或解码失败：原样返回（尽力语义）；②最长边
	// ≤1920：原样零重采样（G9 小图保真）；③最长边 >1920：等比缩放至 1920
	// ——PNG 输入保 PNG（透明通道无损口径），其余输出 JPEG quality 0.85。
	function grmailCompressImage(file) {
		if (!file.type || !file.type.startsWith('image/')) { return grmailReadAsDataURL(file); }
		// D8#14：gif 跳过压缩——Canvas 重采样会静默丢失动画（单帧化），
		// 原样内联保真（U22 登记项收口：动图保动画）
		if (file.type === 'image/gif') { return grmailReadAsDataURL(file); }
		var bmp = null;
		try {
			return createImageBitmap(file).then(function (b) {
				bmp = b;
				if (bmp && Math.max(bmp.width, bmp.height) > GRMAIL_IMG_MAX_EDGE) {
					var scale = GRMAIL_IMG_MAX_EDGE / Math.max(bmp.width, bmp.height);
					var w = Math.max(1, Math.round(bmp.width * scale));
					var h = Math.max(1, Math.round(bmp.height * scale));
					var canvas = document.createElement('canvas');
					canvas.width = w;
					canvas.height = h;
					canvas.getContext('2d').drawImage(bmp, 0, 0, w, h);
					var type = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
					return new Promise(function (r) { canvas.toBlob(function (out) {
						if (bmp && bmp.close) { bmp.close(); }
						r(out ? grmailReadAsDataURL(out) : grmailReadAsDataURL(file));
					}, type, GRMAIL_JPEG_QUALITY); });
				}
				if (bmp && bmp.close) { bmp.close(); }
				return grmailReadAsDataURL(file);
			}).catch(function () {
				if (bmp && bmp.close) { bmp.close(); }
				return grmailReadAsDataURL(file);
			});
		} catch (e) {
			return grmailReadAsDataURL(file);
		}
	}

	// U22 uploader 模块自定义 handler——默认 readAsDataURL 直插语义的压缩版
	// 复刻（逐图压缩→顺序 insertEmbed→光标后移；G9 data: 内联形态不变）。
	// B8（Webmail前端缺陷修复批批一——三轮评审二轮#5/#6 收口）：插入索引随有效
	// 图递增（原恒 range.index 连续插入把前一张挤后——顺序与选择相反）+光标按
	// 有效计数前进（原 urls.length 含失败空串占位——光标错算）。
	function grmailUploaderHandler(range, files) {
		var uploads = Array.from(files).map(function (f) { return grmailCompressImage(f); });
		Promise.all(uploads).then(function (urls) {
			var valid = 0;
			urls.forEach(function (u) {
				if (u) {
					grmailEditor.insertEmbed(range.index + valid, 'image', u);
					valid++;
				}
			});
			grmailEditor.setSelection(range.index + valid);
		});
	}

	// 提交桥接：编辑器容器非表单原生控件——submit 前将 root.innerHTML
	// 写入隐藏 input body（随表单 POST——端点形态零变更）。
	// B-S批 F2：原 form onsubmit 内联改 submit 事件监听（语义等价——
	// 同步写值后表单正常提交）。
	// B2（Webmail前端缺陷修复批批一）：Quill 空产物形态精确 trim（<p><br></p>
	// 等空块序列→空串）——原 innerHTML 恒非空致空白正文绕过校验（服务端
	// htmlBodyBlank 第二道防线对应）；媒体元素（img/video/audio/iframe）零触碰。
	function grmailEditorBlank(html) {
		if (/<img/i.test(html) || /<video/i.test(html) || /<audio/i.test(html) || /<iframe/i.test(html)) {
			return false;
		}
		var t = html.replace(/<p>(?:[\s]|<br\s*\/?>|&nbsp;)*<\/p>/gi, "");
		t = t.replace(/<br\s*\/?>/gi, "");
		return t.replace(/&nbsp;/g, " ").trim() === "";
	}
	function grmailComposeSync() {
		if (grmailEditor) {
			var html = grmailEditor.root.innerHTML;
			if (grmailEditorBlank(html)) { html = ""; }
			document.getElementById('f-body').value = html;
		}
	}

	// G4 写信页全屏覆写：整页容器（含收件人/主题/附件区）requestFullscreen
	// /exitFullscreen 切换（Fullscreen API 原生——纯 JS 零库；ESC 系统默认退出）。
	function grmailComposeFullscreen() {
		var page = document.getElementById('compose-page');
		var btn = document.getElementById('fullscreen-btn');
		if (!document.fullscreenElement) {
			page.requestFullscreen().then(function () {
				btn.textContent = btn.getAttribute('data-exit');
			}).catch(function () { });
		} else {
			document.exitFullscreen().then(function () {
				btn.textContent = btn.getAttribute('data-enter');
			}).catch(function () { });
		}
	}

	// E-A（D8#10）：macOS 平台快捷键提示 ⌘ 记法自适应——U19「统一 Ctrl 记法
	// 不分支」口径的平台面收口（Quill shortKey 内部已平台自适应——本函数仅
	// 提示文案层；服务端渲染 title 保持 Ctrl 记法初值〔u17/u22 断言锚零触碰〕，
	// Mac 客户端加载后改写为 ⌘ 记法；navigator.platform 与 Quill 源码同源口径）。
	function grmailAdaptShortcutTitles() {
		if (!/Mac|iPhone|iPad/.test(navigator.platform || '')) { return; }
		document.querySelectorAll('#compose-toolbar button[title*="(Ctrl+"]').forEach(function (btn) {
			btn.title = btn.title.replace(/\(Ctrl\+([A-Z])\)/g, '(⌘$1)');
		});
	}

	// ── CSV 候选合入（U16 Q5-A 既有——勾选行地址合并进所选 to/cc/bcc 输入框）──
	// B12（批一）：CSRF 取值限定 #compose-form 作用域——原全文档 querySelector
	// 命中顶栏登出表单的隐藏域（值同源故功能未坏——结构耦合：顶栏结构一变即 404）。
	// D6-B：导入成功 toast 回执（grmail.js window 引用——IIFE 隔离跨越）。
	function grmailCsvImport() {
		var f = document.getElementById('csv-file').files[0];
		if (!f) { return; }
		var fd = new FormData();
		fd.append('csrf_token', document.getElementById('compose-form').querySelector('input[name=csrf_token]').value);
		fd.append('file', f);
		fetch('/compose/csv-import', { method: 'POST', body: fd })
			.then(function (r) { return r.ok ? r.text() : Promise.reject(r.status); })
			.then(function (html) {
				document.getElementById('csv-result').innerHTML = html;
				if (window.grmailShowToast) { window.grmailShowToast(document.getElementById('csv-result').textContent.trim().slice(0, 80), "ok"); }
			})
			.catch(function () {
				var pageEl = document.getElementById('compose-page');
				var csvErr = pageEl && pageEl.dataset ? pageEl.dataset.csvErr : '';
				document.getElementById('csv-result').innerHTML = '<p class="error">' + (csvErr || 'CSV parse failed') + '</p>';
			});
	}

	function grmailCsvMerge() {
		var target = document.getElementById('csv-target').value;
		var boxes = document.querySelectorAll('#csv-result input.csv-addr:checked');
		var addrs = Array.from(boxes).map(function (b) { return b.value; });
		if (addrs.length === 0) { return; }
		var el = document.getElementById(target);
		var cur = el.value.trim();
		var merged = cur ? cur + ', ' + addrs.join(', ') : addrs.join(', ');
		el.value = merged;
	}

	// ── 初始化与事件绑定（B-S批 F2：内联 onclick/onsubmit 改绑定）──
	grmailEditorInit();
	grmailAdaptShortcutTitles();
	document.getElementById('csv-parse-btn').addEventListener('click', grmailCsvImport);
	document.getElementById('fullscreen-btn').addEventListener('click', grmailComposeFullscreen);
	// A-1（前端报告批 E-1-A——G2 批准 2026-10-16 10:51）：提交前记录被点按钮的
	// action 值。HTML 规范表单 entry list 构造于 submit 事件之后——B10 禁用按钮
	// 会使按钮 name=action 不入数据集（第三方报告 P0-3：点击发送空体 400）。
	// 捕获阶段 click 委托记录（Ctrl+Enter 的 send.click() 同径触发）。
	var grmailSubmitAction = '';
	document.getElementById('compose-form').addEventListener('click', function (e) {
		var b = e.target.closest && e.target.closest('button[type=submit][name=action]');
		if (b) { grmailSubmitAction = b.value; }
	}, true);
	document.getElementById('compose-form').addEventListener('submit', function () {
		grmailComposeSync();
		// A-1（E-1-A）：动态追加隐藏域承载 action——禁用按钮前入 DOM，随表单
		// 提交出值（降级态 JS 未加载：无监听无禁用，按钮值自然提交——双保险）；
		// 缺省 save_draft 对齐 D2 批隐式提交语义（直接回车=存草稿兜底）。
		var h = document.createElement('input');
		h.type = 'hidden';
		h.name = 'action';
		h.value = grmailSubmitAction || 'save_draft';
		this.appendChild(h);
		// B10（批一）：提交期禁用全部提交按钮——双击重复入队/重复存草稿防线
		// （303 导航离开前的窗口期；校验失败重渲染为新 DOM 自然恢复）。
		var btns = this.querySelectorAll('button[type=submit]');
		for (var i = 0; i < btns.length; i++) { btns[i].disabled = true; }
	});
	// B11（批一）：ESC 退出全屏的按钮文案还原——fullscreenchange 监听（原仅点击
	// 回调改写，ESC 系统退出后按钮停留「退出全屏」态）。
	document.addEventListener('fullscreenchange', function () {
		var btn = document.getElementById('fullscreen-btn');
		if (!btn) { return; }
		btn.textContent = document.fullscreenElement
			? btn.getAttribute('data-exit')
			: btn.getAttribute('data-enter');
	});
	// CSV 合入按钮经服务端片段注入（i18n.go csvImport 片段 id=csv-merge-btn）——
	// 容器级 click 委托（innerHTML 替换后仍生效）
	document.getElementById('csv-result').addEventListener('click', function (e) {
		if (e.target && e.target.id === 'csv-merge-btn') { grmailCsvMerge(); }
	});

	// ── B3（α 批——G2 批准 2026-10-14 20:37）：附件前端大小预检（服务端 35MiB 防线
	// 之外的即时反馈——超限提交前 toast 提示+清空 input，消除「提交→报错→重选」
	// 二次伤害；限值与服务端 readFormAttachments limit 同源 36700160）。
	document.querySelector('#compose-form input[name="attachments"]').addEventListener('change', function () {
		var limit = 36700160;
		var total = 0;
		for (var i = 0; i < this.files.length; i++) { total += this.files[i].size; }
		// A-8（前端报告批）：自定义附件控件文件名回显（原生控件视觉隐藏——
		// 已选状态经 #attach-names 呈现，role=status 播报；多选经 data-files-fmt
		// 双语回显——沿 attach-err dataset 先例）。
		var names = document.getElementById('attach-names');
		if (names) {
			names.textContent = this.files.length === 0 ? '' :
				(this.files.length === 1 ? this.files[0].name :
				(this.files.length + (document.getElementById('compose-page').dataset.filesFmt || ' files selected')));
		}
		if (total > limit) {
			var pageEl = document.getElementById('compose-page');
			var msg = pageEl && pageEl.dataset ? pageEl.dataset.attachErr : '';
			if (window.grmailShowToast) { window.grmailShowToast(msg || 'Attachments exceed limit (35MiB)', 'err'); }
			this.value = '';
			if (names) { names.textContent = ''; }
		}
	});

	// ── B4/E-2-A（α 批——非阻断提示）：收件人地址失焦校验（服务端 err.rcptInvalid
	// 防线保持；逗号分隔逐项最小形态判定：含 @ 且前后非空且不含空格；提示就地
	// label 内追加 p.hint，输入修正后失焦自动清除——role=status 播报）。
	function grmailRcptLooksInvalid(v) {
		var parts = v.split(',');
		for (var i = 0; i < parts.length; i++) {
			var s = parts[i].trim();
			if (!s) { continue; }
			var at = s.indexOf('@');
			if (at <= 0 || at === s.length - 1 || /\s/.test(s)) { return true; }
		}
		return false;
	}
	function grmailRcptHint(el) {
		var hintId = el.id + '-hint';
		var old = document.getElementById(hintId);
		if (old) { old.remove(); }
		var v = el.value.trim();
		if (v === '' || !grmailRcptLooksInvalid(v)) { return; }
		var pageEl = document.getElementById('compose-page');
		var msg = pageEl && pageEl.dataset ? pageEl.dataset.rcptErr : '';
		var p = document.createElement('p');
		p.id = hintId;
		p.className = 'hint';
		p.setAttribute('role', 'status');
		p.textContent = msg || 'Recipient address format may be invalid';
		el.closest('label').appendChild(p);
	}
	['f-to', 'f-cc', 'f-bcc'].forEach(function (id) {
		var el = document.getElementById(id);
		if (el) { el.addEventListener('blur', function () { grmailRcptHint(el); }); }
	});
})();
