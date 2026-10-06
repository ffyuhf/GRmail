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
 *   2026-10-03 16:35:00 | 扩展 | Webmail界面精修批次 F06/F14/F15/F16（G2 批准 2026-10-03 16:22:31） */
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
	 *     事件委托覆盖 HTMX 交换后的新行；全选 checkbox 联动）── */
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
		/* 全选框状态同步（半选态） */
		var allBox = root.querySelector("#batch-form input[name=all]") ||
			root.querySelector(".tool-bar input[name=all]");
		if (allBox && boxes.length > 0) {
			allBox.checked = n === boxes.length;
			allBox.indeterminate = n > 0 && n < boxes.length;
		}
	}
	document.addEventListener("change", function (e) {
		if (e.target && e.target.matches("input.mail-id, #batch-form input[name=all], .tool-bar input[name=all]")) {
			updateSelCount(document);
		}
	});
	/* HTMX 交换后重算（列表刷新/翻页——计数复位） */
	document.body.addEventListener("htmx:afterSwap", function () {
		updateSelCount(document);
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
	 *     .danger/.menu-danger/data-confirm 按钮+批量 delete 表单拦截）── */
	function grmailConfirmText(fallbackZh) {
		var el = document.documentElement;
		return el && el.lang === "en" ? "Proceed with this action?" : fallbackZh;
	}
	document.addEventListener("click", function (e) {
		var btn = e.target.closest && e.target.closest(
			"button.danger, button.menu-danger, button[data-confirm]");
		if (!btn || btn.disabled) { return; }
		var msg = btn.getAttribute("data-confirm") || grmailConfirmText("确定执行该操作？");
		if (!window.confirm(msg)) {
			e.preventDefault();
			e.stopImmediatePropagation();
		}
	}, true);
	document.addEventListener("submit", function (e) {
		var form = e.target;
		if (!form || form.id !== "batch-form") { return; }
		var sel = form.querySelector("select[name=action]");
		if (sel && sel.value === "delete") {
			var msg = document.documentElement.lang === "en"
				? "Delete the selected messages?" : "删除所选邮件？";
			if (!window.confirm(msg)) { e.preventDefault(); }
		}
	}, true);
})();
