/* GRmail Webmail 交互脚本（Webmail设计系统重构批次——自研零依赖）。
 * 职责（计划书 1.2 域6——纯客户端 UI 增强，核心功能零 JS 降级可达）：
 *   ①菜单外点关闭/ESC 关闭（details.menu-host 原生开合的增强——MUI Menu ClickAway 语义）；
 *   ②批量选中计数（.sel-count 文本更新——batch-bar 显隐由 CSS :has 承载，计数为增强）；
 *   ③移动端抽屉路由联动（链接点击后收起抽屉——NavBarFrame location effect 语义）；
 *   ④Webmail界面精修批次四增强（2026-10-03 16:35:00，G2 批准 16:22:31）：
 *     F06 /lang 链接补 next=当前路径（handler 既有校验承载——语言切换保位）；
 *     F14 侧栏文件夹项 Enter 键触发（tabindex=0 键盘可达配套）；
 *     F15 危险操作二次确认（.danger/.menu-danger/data-confirm 委托+批量 delete 表单拦截）；
 *     F16 菜单 ESC 关闭后焦点恢复 summary。
 * 零改动红线：HTMX 端点/表单字段/CSRF 结构零触碰；Quill/CSV 既有内联脚本零关联。
 * SRS 条目：FR-013（交互反馈承载）；参考项目 App.tsx/NavBarFrame.tsx 交互语义。
 * 修改历史：
 *   2026-10-02 17:45:00 | 新建 | Webmail设计系统重构批次阶段A（G2 批准 2026-10-02 17:34:40）
 *   2026-10-03 16:35:00 | 扩展 | Webmail界面精修批次 F06/F14/F15/F16（G2 批准 2026-10-03 16:22:31）
 *   2026-10-11 14:25:00 | 扩展 | Webmail前端缺陷修复批批二（G2 批准 2026-10-11 13:28:34）：
 *     C4 移动端抽屉默认收起（<768 首载 uncheck——SSR checked 桌面 persistent 保持）；
 *     G2 抽屉开关键盘可达（label role=button Enter/Space 触发）+G12 menu-host 开合
 *     aria-expanded 维护（details toggle 事件）；B16 grmailRead 事件→侧栏未读递减
 *     （HX-Trigger 承载——detail.go 置已读联动）；D7 data-copy 复制委托（Token/
 *     恢复码——navigator.clipboard+toast 回执）；C10 admin 过滤零行空态显隐。 */
(function () {
	"use strict";

	/* ── ① 菜单外点关闭 + ESC 关闭（事件委托——HTMX 交换后新菜单自动生效）── */
	document.addEventListener("click", function (e) {
		document.querySelectorAll("details.menu-host[open]").forEach(function (host) {
			if (!host.contains(e.target)) {
				host.removeAttribute("open");
			}
		});
	});
	document.addEventListener("keydown", function (e) {
		if (e.key === "Escape") {
			document.querySelectorAll("details.menu-host[open]").forEach(function (host) {
				host.removeAttribute("open");
				/* F16：ESC 关闭后焦点恢复触发器（键盘菜单闭环） */
				var s = host.querySelector("summary");
				if (s) { s.focus(); }
			});
		}
	});

	/* ── ② 批量选中计数（batch-bar 内 .sel-count——列表勾选即时更新；
	 *     事件委托覆盖 HTMX 交换后的新行；全选 checkbox 联动）──
	 * B1（Webmail前端缺陷修复批批一——三轮评审二轮#4 收口）：本监听器仅匹配行
	 * checkbox（input.mail-id）——原匹配串含全选框致全选事件先被本处理器把全选框
	 * 强制写回未选态、⑤b 联动再读该值反向取消全部行（全选完全失效）；全选框的
	 * 行联动与计数统一归 ⑤b（触发源互斥——职责分离根治互踩）。 */
	function updateSelCount(scope) {
		var root = scope || document;
		var boxes = root.querySelectorAll("input.mail-id");
		var n = 0;
		boxes.forEach(function (b) {
			if (b.checked) { n++; }
		});
		root.querySelectorAll(".sel-count").forEach(function (el) {
			el.textContent = el.getAttribute("data-fmt").replace("%d", String(n));
		});
		/* E-4-A（批五——G2 批准 2026-10-13 08:42:57 五组候选全 A）：.batch-active 兜底
		 * 类——批量条常驻半透明形态下，无 :has 浏览器（Safari≤15.3）经 JS 恢复全交互
		 * （:has 命中时与 CSS 双通道一致）；事件委托覆盖 HTMX 交换后新列表。 */
		root.querySelectorAll(".batch-bar").forEach(function (bar) {
			bar.classList.toggle("batch-active", n > 0);
		});
		/* 全选框状态同步（半选态）——仅行变更后的回写（全选框自身事件归 ⑤b） */
		var allBox = root.querySelector("#batch-form input[name=all]") ||
			root.querySelector(".tool-bar input[name=all]");
		if (allBox && boxes.length > 0) {
			allBox.checked = n === boxes.length;
			allBox.indeterminate = n > 0 && n < boxes.length;
		}
	}
	document.addEventListener("change", function (e) {
		if (e.target && e.target.matches("input.mail-id")) {
			updateSelCount(document);
		}
	});
	/* HTMX 交换后重算（列表刷新/翻页——计数复位）+D6-B：交换区错误块伴生 toast
	 * （.error role=alert 之外的视觉浮层回执——浏览器可见性增强） */
	document.body.addEventListener("htmx:afterSwap", function (e) {
		updateSelCount(document);
		if (e && e.target && e.target.querySelector) {
			var blk = e.target.querySelector(".error");
			if (blk && window.grmailShowToast) {
				window.grmailShowToast(blk.textContent.trim(), "err");
			}
		}
	});
	updateSelCount(document);

	/* ── ③ 移动端抽屉联动（侧栏链接点击后收起——NavBarFrame isMobile effect）── */
	document.addEventListener("click", function (e) {
		var toggle = document.getElementById("nav-toggle");
		if (!toggle || !toggle.checked) { return; }
		var sidebar = e.target.closest && e.target.closest(".sidebar");
		if (sidebar && e.target.closest("a, button, summary") && !e.target.closest("details:not([open])")) {
			/* 移动端视口内才收起（桌面 checked=展开态不动作） */
			if (window.matchMedia("(max-width: 767.98px)").matches) {
				toggle.checked = false;
			}
		}
	});

	/* ── ④a F06：语言切换链接补 next=当前路径（DOMContentLoaded 一次性——
	 *     /lang handler 既有 next 校验承载，切换后回当前页）── */
	function grmailLangNext() {
		document.querySelectorAll('a[href^="/lang?"]').forEach(function (a) {
			try {
				var url = new URL(a.getAttribute("href"), window.location.origin);
				if (!url.searchParams.get("next")) {
					url.searchParams.set("next", window.location.pathname + window.location.search);
					a.setAttribute("href", url.pathname + "?" + url.searchParams.toString());
				}
			} catch (err) { /* 非法 href 兜底不设 */ }
		});
	}
	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", grmailLangNext);
	} else {
		grmailLangNext();
	}

	/* ── C4（批二）：移动端抽屉默认收起——<768 首载 uncheck（桌面 SSR checked
	 *     persistent 展开保持；禁 JS 降级=移动保持展开〔noscript 提示已有〕）。 ── */
	if (window.matchMedia("(max-width: 767.98px)").matches) {
		var nt = document.getElementById("nav-toggle");
		if (nt) { nt.checked = false; }
	}

	/* ── G2（批二）：抽屉开关键盘可达——label role=button 配套 Enter/Space 触发
	 *     （click 同步 checkbox 翻转——label for 语义聚焦触发原生点击即可）。 ── */
	document.addEventListener("keydown", function (e) {
		if ((e.key === "Enter" || e.key === " ") && e.target &&
			e.target.matches && e.target.matches("label.nav-toggle")) {
			e.preventDefault();
			e.target.click();
		}
	});

	/* ── G12（批二）：menu-host 开合 aria-expanded 维护（details toggle 事件
	 *     委托——HTMX 交换后新菜单同生效；初始态 DOMContentLoaded 扫描）。 ── */
	function syncMenuAria(host) {
		var s = host.querySelector("summary");
		if (s) { s.setAttribute("aria-expanded", host.open ? "true" : "false"); }
	}
	document.addEventListener("toggle", function (e) {
		if (e.target && e.target.matches && e.target.matches("details.menu-host")) {
			syncMenuAria(e.target);
		}
	}, true);
	function syncAllMenuAria() {
		document.querySelectorAll("details.menu-host").forEach(syncMenuAria);
	}
	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", syncAllMenuAria);
	} else {
		syncAllMenuAria();
	}

	/* ── B16（批二）：详情置已读 HX-Trigger 事件（detail.go HX-Trigger: grmailRead
	 *     =folderID）→ 侧栏对应文件夹未读数就地递减（aria 图标同步——无未读隐藏）。 ── */
	document.body.addEventListener("grmailRead", function (e) {
		var fid = e && e.detail && (e.detail.folderID || e.detail);
		if (fid === undefined || fid === null) { return; }
		document.querySelectorAll(".folder-item").forEach(function (a) {
			var m = a.getAttribute("href") && a.getAttribute("href").match(/[?&]folder=(\d+)/);
			if (!m || parseInt(m[1], 10) !== parseInt(fid, 10)) { return; }
			var u = a.querySelector(".unread");
			if (!u) { return; }
			var n = parseInt(u.textContent, 10) - 1;
			if (n > 0) { u.textContent = String(n); } else { u.remove(); }
		});
	});

	/* ── D7（批二）：data-copy 复制委托（Token 明文/恢复码集——navigator.clipboard
	 *     需安全上下文〔HTTPS/localhost〕；失败降级 execCommand+toast 回执）。 ── */
	document.addEventListener("click", function (e) {
		var btn = e.target.closest && e.target.closest("[data-copy]");
		if (!btn || btn.disabled) { return; }
		var text = btn.getAttribute("data-copy");
		function done(ok) {
			if (window.grmailShowToast) {
				window.grmailShowToast(ok ? btn.getAttribute("data-ok-msg") || "✓" : "✗", ok ? "ok" : "err");
			}
		}
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
		} else {
			var ta = document.createElement("textarea");
			ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
			document.body.appendChild(ta); ta.select();
			try { done(document.execCommand("copy")); } catch (err) { done(false); }
			ta.remove();
		}
	});

	/* ── ④b F14：侧栏文件夹项 Enter 键触发（tabindex=0 配套——键盘切换文件夹）── */
	document.addEventListener("keydown", function (e) {
		if (e.key === "Enter" && e.target && e.target.matches &&
			e.target.matches('.folder-item[tabindex="0"]')) {
			e.preventDefault();
			e.target.click();
		}
	});

	/* ── ④d G5（管理员主体增强批次 D12）：发信地址前缀自动补全——blur/Enter 时机
	 *     检测 #f-from 值非空且不含 @ 时追加「@主域」（data-domain 承载；已含 @ /
	 *     空值零动作——完整地址与空语义不扰）── */
	function grmailFromComplete(input) {
		var v = input.value.trim();
		var domain = input.getAttribute("data-domain");
		if (v && domain && v.indexOf("@") < 0) {
			input.value = v + "@" + domain;
		}
	}
	document.addEventListener("blur", function (e) {
		if (e.target && e.target.id === "f-from") { grmailFromComplete(e.target); }
	}, true);
	document.addEventListener("keydown", function (e) {
		if (e.key === "Enter" && e.target && e.target.id === "f-from") {
			grmailFromComplete(e.target);
		}
	});

	/* ── ④c F15：危险操作二次确认（捕获阶段先于 submit——
	 *     .danger/.menu-danger/data-confirm 按钮+批量表单拦截）。
	 * B13（Webmail前端缺陷修复批批一——三轮评审一轮#26/二轮#10/#11 收口）：
	 *   ①文案统一 data-confirm 属性承载（服务端 Tr 渲染——废除 JS 双语三元两套
	 *     自维护；默认文案读 <html data-confirm-default>）；
	 *   ②覆盖面补齐：批量「移动到垃圾箱」等价删除路径纳入确认（option data-kind
	 *     判定目标——mail_list.templ 批量表单 data-confirm-* 属性配套）。 ── */
	function grmailDefaultConfirm() {
		var el = document.documentElement;
		return (el && el.dataset && el.dataset.confirmDefault) || "确定执行该操作？";
	}
	document.addEventListener("click", function (e) {
		var btn = e.target.closest && e.target.closest(
			"button.danger, button.menu-danger, button[data-confirm]");
		if (!btn || btn.disabled) { return; }
		var msg = btn.getAttribute("data-confirm") || grmailDefaultConfirm();
		if (!window.confirm(msg)) {
			e.preventDefault();
			e.stopImmediatePropagation();
		}
	}, true);
	document.addEventListener("submit", function (e) {
		var form = e.target;
		if (!form || form.id !== "batch-form") { return; }
		var sel = form.querySelector("select[name=action]");
		if (!sel) { return; }
		var msg = "";
		if (sel.value === "delete") {
			msg = form.getAttribute("data-confirm-delete") || grmailDefaultConfirm();
		} else if (sel.value === "move") {
			var opt = form.querySelector("select[name=target] option:checked");
			if (opt && opt.getAttribute("data-kind") === "trash") {
				msg = form.getAttribute("data-confirm-move-trash") || grmailDefaultConfirm();
			}
		}
		if (msg && !window.confirm(msg)) { e.preventDefault(); }
	}, true);

	/* ── D6-B（Webmail前端缺陷修复批批一）：toast 瞬态反馈组件接入（.toast CSS
	 *     既有——定位/生命周期动画；5.6s 后 JS 移除兜底〔reduced-motion 豁免下
	 *     动画 none——移除是唯一清理路径〕）。消费点：afterSwap 错误块伴生（②内）+
	 *     CSV 导入成功（compose.js 经 window 引用）。 ── */
	window.grmailShowToast = function (msg, kind) {
		var t = document.createElement("div");
		t.className = "toast" + (kind ? " toast-" + kind : "");
		t.setAttribute("role", "status");
		t.textContent = msg;
		document.body.appendChild(t);
		setTimeout(function () {
			if (t.parentNode) { t.parentNode.removeChild(t); }
		}, 5600);
	};

	/* ── ⑤ B-S批 F2（裁决 A 2026-10-09 13:34）：内联事件外迁承载（CSP
	 *     script-src 'self' 配套——原模板 onclick/onchange/oninput 清除） ── */

	/* ⑤a admin 邮箱管理页复合过滤（迁自 admin.templ 内联脚本——G4/D3
	 * 地址+状态双条件与语义零变化；元素不存在页面零动作）。
	 * B8②（批五）：C10 联动落码——admin.templ 注释声称的「过滤零行空态显隐
	 * #admin-empty」自本批真实承载（原 grmail.js 零实现——过滤零行页面空白无反馈）。 */
	function grmailApplyAdminFilter(q, status) {
		var anyVisible = false;
		document.querySelectorAll("#admin-rows tr[data-addr]").forEach(function (r) {
			var addrOk = r.getAttribute("data-addr").indexOf(q) >= 0;
			var statusOk = !status || r.getAttribute("data-status") === status;
			var show = addrOk && statusOk;
			r.style.display = show ? "" : "none";
			if (show) { anyVisible = true; }
		});
		var empty = document.getElementById("admin-empty");
		if (empty) { empty.hidden = anyVisible; }
	}
	document.addEventListener("change", function (e) {
		if (e.target && e.target.id === "admin-status-filter") {
			var q = (document.getElementById("admin-filter") || {}).value || "";
			grmailApplyAdminFilter(q.toLowerCase(), e.target.value);
		}
	});
	document.addEventListener("input", function (e) {
		if (e.target && e.target.id === "admin-filter") {
			var sel = document.getElementById("admin-status-filter");
			var status = sel ? sel.value : "";
			grmailApplyAdminFilter(e.target.value.toLowerCase(), status);
		}
	});

	/* ⑤b 批量全选联动（迁自 mail_list.templ onclick——全选框勾选联动全部行；
	 *     B1：联动后同步计数（原②在 all 事件上写回全选框致双向互锁——见②注） */
	document.addEventListener("change", function (e) {
		if (e.target && e.target.matches &&
			e.target.matches("#batch-form input[name=all], .tool-bar input[name=all]") &&
			e.target.type === "checkbox") {
			var checked = e.target.checked;
			document.querySelectorAll("input.mail-id").forEach(function (b) { b.checked = checked; });
			updateSelCount(document);
		}
	});

	/* ── C3（批五）：菜单键盘导航（↑↓/Home/End 项间遍历）与移动端抽屉焦点管理——
	 *     增强档纯新增（既有外点/ESC 关闭与禁 JS 降级保持；role=menu 键盘模型补齐）。 ── */
	document.addEventListener("keydown", function (e) {
		if (e.key !== "ArrowDown" && e.key !== "ArrowUp" && e.key !== "Home" && e.key !== "End") { return; }
		var host = e.target.closest && e.target.closest("details.menu-host");
		if (!host || !host.open) { return; }
		var items = Array.prototype.slice.call(host.querySelectorAll(".menu a, .menu button"));
		if (!items.length) { return; }
		var idx = items.indexOf(document.activeElement);
		e.preventDefault();
		if (e.key === "Home") { idx = 0; }
		else if (e.key === "End") { idx = items.length - 1; }
		else if (e.key === "ArrowDown") { idx = (idx + 1 + items.length) % items.length; }
		else { idx = (idx - 1 + items.length) % items.length; }
		items[idx].focus();
	});
	/* C3：移动端抽屉 ESC 关闭+焦点返还触发器（沿 F16 焦点恢复先例——键盘关闭路径完整化）。 */
	document.addEventListener("keydown", function (e) {
		if (e.key !== "Escape") { return; }
		var toggle = document.getElementById("nav-toggle");
		if (!toggle || !toggle.checked) { return; }
		if (!window.matchMedia("(max-width: 767.98px)").matches) { return; }
		toggle.checked = false;
		var label = document.querySelector("label.nav-toggle");
		if (label) { label.focus(); }
	});
	/* C3：开抽屉焦点入抽屉首项（移动视口——焦点随面板转移，读屏/键盘用户不滞留触发器）。 */
	document.addEventListener("change", function (e) {
		if (!e.target || e.target.id !== "nav-toggle") { return; }
		if (!e.target.checked || !window.matchMedia("(max-width: 767.98px)").matches) { return; }
		var first = document.querySelector(".sidebar .folder-item, .sidebar summary");
		if (first) { first.focus(); }
	});

	/* ── D2（批五——干系人指示逐字「D2 回车误发缓解 Ctrl+回车发送 直接回车是换行处理。」
	 *     2026-10-13 08:42:57 随 G2 批准一体）：写信表单回车语义——①Ctrl/Cmd+Enter 显式
	 *     触发发送提交；②直接 Enter 于单行输入框 preventDefault 不触发表单隐式提交
	 *     （单行框换行物理不适用——语义为不提交；Quill 编辑器 contenteditable 不在
	 *     拦截面，Enter 保持换行默认）。与 E-3-A 草稿按钮 DOM 前置（compose.templ）
	 *     构成三层防线。 ── */
	document.addEventListener("keydown", function (e) {
		if (e.key !== "Enter") { return; }
		var form = e.target.closest && e.target.closest("#compose-form");
		if (!form || e.target.tagName === "BUTTON" || e.target.tagName === "A") { return; }
		if (e.ctrlKey || e.metaKey) {
			e.preventDefault();
			var send = form.querySelector('button[name="action"][value="send"]');
			if (send && !send.disabled) { send.click(); }
			return;
		}
		if (e.target.matches && e.target.matches(
			'input:not([type="checkbox"]):not([type="radio"]):not([type="file"]):not([type="submit"]):not([type="button"])')) {
			e.preventDefault();
		}
	});
})();
