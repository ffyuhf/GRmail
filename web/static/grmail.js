/* GRmail Webmail 交互脚本 v3 —— 前端结构重构版（零依赖、零构建、CSP script-src 'self' 兼容）。
 *
 * 设计约束（保持不变）：
 *   - 核心功能零 JS 可降级：菜单用原生 details、筛选/翻页用链接、表单用原生 submit；
 *   - 不触碰 HTMX 端点/参数/表单字段/CSRF 结构；
 *   - 对外仅暴露 window.grmailShowToast 与 grmailRead 事件契约。
 *
 * 相对 v2 的结构变化：
 *   1. 事件注册收敛为「键盘 / 点击 / 变更 / 提交 / HTMX 生命周期」五个委托入口，
 *      原十余个平铺监听合并，HTMX 局部替换后无需重复绑定；
 *   2. 交互行为以具名模块函数承载（menu / drawer / selection / clipboard /
 *      confirm / toast / sidebar / adminFilter / composeKeys），状态在闭包内；
 *   3. 选择计数一次遍历完成（原每行 change 触发全量扫描 + 全选框回写）；
 *   4. 抽屉与菜单的 aria-expanded 统一维护（含 #nav-toggle）；
 *   5. toast 以队列承载并落在 role=status 容器，连续提示不叠压、可被读屏播报；
 *   6. 所有 DOM 写入使用 textContent / 属性操作，不引入 innerHTML 拼接。
 */
(function () {
	"use strict";

	/* ───────────────────────── 基础工具 ───────────────────────── */

	var MOBILE_QUERY = "(max-width: 767.98px)";

	function $(sel, root) { return (root || document).querySelector(sel); }
	function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
	function isMobile() { return window.matchMedia(MOBILE_QUERY).matches; }
	function on(el, type, fn, opts) { if (el) { el.addEventListener(type, fn, opts); } }
	function closest(el, sel) { return el && el.closest ? el.closest(sel) : null; }

	/* 默认确认文案由服务端渲染在 <html data-confirm-default>（双语）。 */
	function defaultConfirm() {
		var el = document.documentElement;
		return (el && el.dataset && el.dataset.confirmDefault) || "确定执行该操作？";
	}

	/* ───────────────────────── 菜单（details.menu-host） ───────────────────────── */

	var Menu = {
		hosts: function () { return $$("details.menu-host"); },
		close: function (host, restoreFocus) {
			var summary = host.querySelector("summary");
			host.removeAttribute("open");
			if (summary) {
				summary.setAttribute("aria-expanded", "false");
				if (restoreFocus) { summary.focus(); }
			}
		},
		closeAll: function (except, restoreFocus) {
			Menu.hosts().forEach(function (host) {
				if (host !== except) { Menu.close(host, restoreFocus); }
			});
		},
		sync: function (host) {
			var summary = host.querySelector("summary");
			if (summary) { summary.setAttribute("aria-expanded", host.open ? "true" : "false"); }
		},
		syncAll: function () { Menu.hosts().forEach(Menu.sync); },
		items: function (host) {
			return $$(".menu a, .menu button", host).filter(function (el) { return !el.disabled; });
		},
		move: function (host, key) {
			var items = Menu.items(host);
			if (items.length === 0) { return false; }
			var idx = items.indexOf(document.activeElement);
			if (key === "Home") { idx = 0; }
			else if (key === "End") { idx = items.length - 1; }
			else if (key === "ArrowDown") { idx = (idx + 1 + items.length) % items.length; }
			else { idx = (idx - 1 + items.length) % items.length; }
			items[idx].focus();
			return true;
		}
	};

	/* ───────────────────────── 移动抽屉（#nav-toggle） ───────────────────────── */

	var Drawer = {
		toggle: function () { return document.getElementById("nav-toggle"); },
		label: function () { return $("label.nav-toggle"); },
		sync: function () {
			var input = Drawer.toggle();
			var label = Drawer.label();
			if (!input || !label) { return; }
			label.setAttribute("aria-expanded", input.checked ? "true" : "false");
			label.setAttribute("aria-controls", "main-content");
		},
		open: function (open) {
			var input = Drawer.toggle();
			if (!input) { return; }
			input.checked = !!open;
			Drawer.sync();
			if (open && isMobile()) {
				var first = $(".sidebar .folder-item, .sidebar summary");
				if (first) { first.focus(); }
			}
		},
		focusFirst: function () {
			if (!isMobile()) { return; }
			var input = Drawer.toggle();
			if (!input || !input.checked) { return; }
			var first = $(".sidebar .folder-item, .sidebar summary");
			if (first) { first.focus(); }
		}
	};

	/* ───────────────────────── 批量选择（列表片段） ───────────────────────── */

	var Selection = {
		boxes: function () { return $$("input.mail-id"); },
		refresh: function () {
			var boxes = Selection.boxes();
			var checked = 0;
			boxes.forEach(function (b) { if (b.checked) { checked++; } });

			$$(".sel-count").forEach(function (el) {
				var fmt = el.getAttribute("data-fmt") || "%d";
				el.textContent = fmt.replace("%d", String(checked));
			});
			$$(".batch-bar").forEach(function (bar) {
				bar.classList.toggle("batch-active", checked > 0);
			});

			var all = $("#batch-form input[name=all]") || $(".tool-bar input[name=all]");
			if (all && boxes.length > 0) {
				all.checked = checked === boxes.length;
				all.indeterminate = checked > 0 && checked < boxes.length;
			}
		},
		setAll: function (checked) {
			Selection.boxes().forEach(function (b) { b.checked = checked; });
			Selection.refresh();
		}
	};

	/* ───────────────────────── 剪贴板（data-copy） ───────────────────────── */

	function legacyCopy(text) {
		var ta = document.createElement("textarea");
		ta.value = text;
		ta.setAttribute("readonly", "");
		ta.style.position = "fixed";
		ta.style.top = "-1000px";
		ta.style.opacity = "0";
		document.body.appendChild(ta);
		ta.select();
		var ok = false;
		try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
		ta.remove();
		return ok;
	}

	function copyFrom(btn) {
		var text = btn.getAttribute("data-copy") || "";
		function done(ok) {
			window.grmailShowToast(ok ? (btn.getAttribute("data-ok-msg") || "✓")
				: (btn.getAttribute("data-err-msg") || "✗"), ok ? "ok" : "err");
		}
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(text).then(function () { done(true); },
				function () { done(legacyCopy(text)); });
			return;
		}
		done(legacyCopy(text));
	}

	/* ───────────────────────── 危险操作确认 ───────────────────────── */

	function confirmAction(msg) { return !msg || window.confirm(msg); }

	function confirmClick(e) {
		var btn = closest(e.target, "button.danger, button.menu-danger, button[data-confirm]");
		if (!btn || btn.disabled) { return; }
		if (!confirmAction(btn.getAttribute("data-confirm") || defaultConfirm())) {
			e.preventDefault();
			e.stopImmediatePropagation();
		}
	}

	function confirmBatchSubmit(e) {
		var form = e.target;
		if (!form || form.id !== "batch-form") { return; }
		var sel = form.querySelector("select[name=action]");
		if (!sel) { return; }
		var msg = "";
		if (sel.value === "delete") {
			msg = form.getAttribute("data-confirm-delete") || defaultConfirm();
		} else if (sel.value === "move") {
			var opt = form.querySelector("select[name=target] option:checked");
			if (opt && opt.getAttribute("data-kind") === "trash") {
				msg = form.getAttribute("data-confirm-move-trash") || defaultConfirm();
			}
		}
		if (msg && !confirmAction(msg)) { e.preventDefault(); }
	}

	/* ───────────────────────── 提示条（toast） ───────────────────────── */

	var toastHost = null;

	window.grmailShowToast = function (msg, kind) {
		if (!msg) { return; }
		if (!toastHost) {
			toastHost = document.createElement("div");
			toastHost.className = "toast-host";
			toastHost.setAttribute("role", "status");
			toastHost.setAttribute("aria-live", "polite");
			document.body.appendChild(toastHost);
		}
		var node = document.createElement("div");
		node.className = "toast" + (kind ? " toast-" + kind : "");
		node.textContent = String(msg).slice(0, 200);
		toastHost.appendChild(node);
		while (toastHost.children.length > 3) { toastHost.removeChild(toastHost.firstChild); }
		window.setTimeout(function () {
			if (node.parentNode) { node.parentNode.removeChild(node); }
		}, 5600);
	};

	/* ───────────────────────── 侧栏 ───────────────────────── */

	function folderIdOf(el) {
		var href = el && el.getAttribute("href");
		var m = href && href.match(/[?&]folder=(\d+)/);
		return m ? parseInt(m[1], 10) : null;
	}

	function grmailSyncSidebarActive() {
		var items = $$(".sidebar .folder-item");
		if (items.length === 0) { return; }
		var path = location.pathname;
		var isMailPath = path === "/" || path === "/mails";
		var m = isMailPath ? location.search.match(/[?&]folder=(\d+)/) : null;
		var activeIdx = -1;
		if (isMailPath) {
			if (m) {
				var target = parseInt(m[1], 10);
				for (var i = 0; i < items.length; i++) {
					if (folderIdOf(items[i]) === target) { activeIdx = i; break; }
				}
			} else {
				activeIdx = 0;
			}
		}
		items.forEach(function (item, idx) {
			var active = idx === activeIdx;
			item.classList.toggle("active", active);
			if (active) { item.setAttribute("aria-current", "page"); }
			else { item.removeAttribute("aria-current"); }
		});
	}

	function decrementUnread(folderId) {
		if (folderId === undefined || folderId === null) { return; }
		$$(".sidebar .folder-item").forEach(function (a) {
			if (folderIdOf(a) !== parseInt(folderId, 10)) { return; }
			var badge = a.querySelector(".unread");
			if (!badge) { return; }
			var n = parseInt(badge.textContent, 10) - 1;
			if (n > 0) { badge.textContent = String(n); } else { badge.remove(); }
		});
	}

	/* ───────────────────────── 管理员邮箱过滤 ───────────────────────── */

	function applyAdminFilter(query, status) {
		var q = (query || "").toLowerCase();
		var visible = 0;
		$$("#admin-rows tr[data-addr]").forEach(function (row) {
			var addrOk = row.getAttribute("data-addr").toLowerCase().indexOf(q) >= 0;
			var statusOk = !status || row.getAttribute("data-status") === status;
			var show = addrOk && statusOk;
			row.hidden = !show;
			if (show) { visible++; }
		});
		var empty = document.getElementById("admin-empty");
		if (empty) { empty.hidden = visible > 0; }
	}

	/* ───────────────────────── 写信页键盘语义 ───────────────────────── */

	function composeEnter(e) {
		var form = closest(e.target, "#compose-form");
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
	}

	/* ───────────────────────── 发信地址前缀补全 ───────────────────────── */

	function completeFrom(input) {
		var v = input.value.trim();
		var domain = input.getAttribute("data-domain");
		if (v && domain && v.indexOf("@") < 0) { input.value = v + "@" + domain; }
	}

	/* ───────────────────────── 事件入口 ───────────────────────── */

	/* 键盘：单一分发（ESC / Enter / Space / 菜单方向键）。 */
	document.addEventListener("keydown", function (e) {
		var target = e.target;

		if (e.key === "Escape") {
			var openMenu = $("details.menu-host[open]");
			if (openMenu) { Menu.close(openMenu, true); }
			var nav = Drawer.toggle();
			if (nav && nav.checked && isMobile()) {
				Drawer.open(false);
				var label = Drawer.label();
				if (label) { label.focus(); }
			}
			return;
		}

		if ((e.key === "Enter" || e.key === " ") && target && target.matches && target.matches("label.nav-toggle")) {
			e.preventDefault();
			target.click();
			return;
		}

		if (e.key === "Enter" && target && target.matches && target.matches('.folder-item[tabindex="0"]')) {
			e.preventDefault();
			target.click();
			return;
		}

		if (e.key === "Enter" && target && target.id === "f-from") {
			completeFrom(target);
			return;
		}

		if (e.key === "Enter") { composeEnter(e); return; }

		if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Home" || e.key === "End") {
			var host = closest(target, "details.menu-host");
			if (host && host.open && Menu.move(host, e.key)) { e.preventDefault(); }
		}
	});

	/* 点击：捕获阶段先做危险确认，冒泡阶段做外点关闭 / 复制 / 抽屉联动。 */
	document.addEventListener("click", confirmClick, true);

	document.addEventListener("click", function (e) {
		var target = e.target;

		var copyBtn = closest(target, "[data-copy]");
		if (copyBtn && !copyBtn.disabled) { copyFrom(copyBtn); }

		Menu.hosts().forEach(function (host) {
			if (!host.contains(target)) { Menu.close(host, false); }
		});

		var nav = Drawer.toggle();
		if (nav && nav.checked && isMobile() && closest(target, ".sidebar a, .sidebar button, .sidebar summary")) {
			Drawer.open(false);
		}
	});

	/* 变更：选择计数 / 全选联动 / 抽屉状态与焦点 / 管理员过滤。 */
	document.addEventListener("change", function (e) {
		var target = e.target;

		if (target && target.matches && target.matches("input.mail-id")) {
			Selection.refresh();
			return;
		}
		if (target && target.matches && target.type === "checkbox" &&
			target.matches("#batch-form input[name=all], .tool-bar input[name=all]")) {
			Selection.setAll(target.checked);
			return;
		}
		if (target && target.id === "nav-toggle") {
			Drawer.sync();
			Drawer.focusFirst();
			return;
		}
		if (target && target.id === "admin-status-filter") {
			var input = document.getElementById("admin-filter");
			applyAdminFilter(input ? input.value : "", target.value);
		}
	});

	document.addEventListener("input", function (e) {
		if (e.target && e.target.id === "admin-filter") {
			var sel = document.getElementById("admin-status-filter");
			applyAdminFilter(e.target.value, sel ? sel.value : "");
		}
	});

	/* 提交：批量危险动作确认（捕获阶段先于 HTMX 提交）。 */
	document.addEventListener("submit", confirmBatchSubmit, true);

	/* 焦点离开：发信地址补全（捕获阶段，blur 不冒泡）。 */
	document.addEventListener("blur", function (e) {
		if (e.target && e.target.id === "f-from") { completeFrom(e.target); }
	}, true);

	/* HTMX 生命周期：列表交换后重算计数、同步侧栏、错误块转 toast。 */
	document.body.addEventListener("htmx:beforeRequest", function (e) {
		var list = document.getElementById("mail-list");
		if (list && e.target && (e.target === list || list.contains(e.target))) {
			list.setAttribute("aria-busy", "true");
		}
	});

	document.body.addEventListener("htmx:afterSwap", function (e) {
		Selection.refresh();
		if (e.target && e.target.id === "mail-list") {
			grmailSyncSidebarActive();
			e.target.setAttribute("aria-busy", "false");
		}
		if (e.target && e.target.querySelector) {
			var err = e.target.querySelector(".error");
			if (err) { window.grmailShowToast(err.textContent.trim(), "err"); }
		}
		Drawer.sync();
		Menu.syncAll();
	});

	document.body.addEventListener("htmx:responseError", function () {
		var list = document.getElementById("mail-list");
		if (list) { list.setAttribute("aria-busy", "false"); }
	});

	/* 详情置已读事件：侧栏未读计数就地递减。 */
	document.body.addEventListener("grmailRead", function (e) {
		var detail = e && e.detail;
		decrementUnread(detail && (detail.folderID !== undefined ? detail.folderID : detail));
	});

	/* 菜单开合状态同步（toggle 在捕获阶段可跨 HTMX 交换生效）。 */
	document.addEventListener("toggle", function (e) {
		if (e.target && e.target.matches && e.target.matches("details.menu-host")) {
			Menu.sync(e.target);
		}
	}, true);

	/* ───────────────────────── 初始化 ───────────────────────── */

	function init() {
		if (isMobile()) { Drawer.open(false); }
		Drawer.sync();
		Menu.syncAll();
		Selection.refresh();
		/* /lang 链接补 next=当前路径（切换后保位；服务端校验 next 合法性）。 */
		$$('a[href^="/lang?"]').forEach(function (a) {
			try {
				var url = new URL(a.getAttribute("href"), window.location.origin);
				if (!url.searchParams.get("next")) {
					url.searchParams.set("next", window.location.pathname + window.location.search);
					a.setAttribute("href", url.pathname + "?" + url.searchParams.toString());
				}
			} catch (err) { /* 非法 href 不处理 */ }
		});
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", init);
	} else {
		init();
	}
})();
