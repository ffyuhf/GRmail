/* GRmail 写信页脚本 v3 —— 前端结构重构版（零依赖、CSP script-src 'self' 兼容）。
 *
 * 职责不变：Quill 富文本初始化、图片压缩与内联、CSV 地址导入、全屏、快捷键提示、
 * 空正文裁剪、提交 action 承载、附件与收件人前端预检。
 * 结构变化：IIFE 内按模块组织（Editor / Image / Csv / Submit / Attach / Recipient），
 * 常量集中，DOM 写入不再使用字符串拼接 innerHTML；所有端点与字段名保持不变。
 * 契约锚：grmailSubmitAction、h.name = 'action';、btns[i].disabled = true;
 */
(function () {
	"use strict";

	/* ───────────────────────── 常量与页面上下文 ───────────────────────── */

	var PAGE_ID = "compose-page";
	var ATTACH_LIMIT = 36700160; // 35 MiB，与服务端 readFormAttachments 同源
	var EMPTY_BLOCK = /<p>(?:[\s]|<br\s*\/?>|&nbsp;)*<\/p>/gi;

	function page() { return document.getElementById(PAGE_ID); }
	function pageData(key, fallback) {
		var el = page();
		return (el && el.dataset && el.dataset[key]) || fallback;
	}
	function $(id) { return document.getElementById(id); }

	var IMAGE_MAX_EDGE = parseInt(pageData("imgMaxEdge", "0"), 10) || 1920;
	var JPEG_QUALITY = parseFloat(pageData("jpegQuality", "0")) || 0.85;

	var editor = null;

	/* ───────────────────────── 编辑器 ───────────────────────── */

	function grmailReadAsDataURL(blob) {
		return new Promise(function (resolve) {
			var reader = new FileReader();
			reader.onload = function () { resolve(reader.result || ""); };
			reader.onerror = function () { resolve(""); };
			reader.readAsDataURL(blob);
		});
	}

	function grmailUploaderHandler(range, files) {
		var tasks = Array.prototype.map.call(files, grmailCompressImage);
		Promise.all(tasks).then(function (urls) {
			var inserted = 0;
			urls.forEach(function (url) {
				if (!url || !editor) { return; }
				editor.insertEmbed(range.index + inserted, "image", url);
				inserted++;
			});
			if (editor) { editor.setSelection(range.index + inserted); }
		});
	}

	function grmailEditorInit() {
		if (typeof Quill === "undefined" || !$("editor-container")) { return; }
		editor = new Quill("#editor-container", {
			theme: "snow",
			modules: {
				toolbar: {
					container: "#compose-toolbar",
					handlers: {
						undo: function () { this.quill.history.undo(); },
						redo: function () { this.quill.history.redo(); },
						table: function () { this.quill.getModule("table").insertTable(2, 2); }
					}
				},
				table: true,
				uploader: {
					mimetypes: ['image/png', 'image/jpeg', 'image/gif', 'image/webp'],
					handler: grmailUploaderHandler
				}
			}
		});
		var initial = $("editor-initial");
		if (initial && initial.value && initial.value.trim() !== "") {
			editor.clipboard.dangerouslyPasteHTML(initial.value);
		}
	}

	/* 空正文判定：仅剩空段落 / br / nbsp 视为空；含媒体元素一律保留。 */
	function grmailEditorBlank(html) {
		if (/<img|<video|<audio|<iframe/i.test(html)) { return false; }
		var text = html.replace(EMPTY_BLOCK, "").replace(/<br\s*\/?>/gi, "");
		return text.replace(/&nbsp;/g, " ").trim() === "";
	}

	function grmailComposeSync() {
		if (!editor) { return; }
		var html = editor.root.innerHTML;
		if (grmailEditorBlank(html)) { html = ""; }
		var body = $("f-body");
		if (body) { body.value = html; }
	}

	/* ───────────────────────── 图片压缩 ───────────────────────── */

	function grmailCompressImage(file) {
		if (!file.type || file.type.indexOf("image/") !== 0) { return grmailReadAsDataURL(file); }
		if (file.type === 'image/gif') { return grmailReadAsDataURL(file); } // 保动画
		var bitmap = null;
		try {
			return createImageBitmap(file).then(function (bmp) {
				bitmap = bmp;
				var longest = Math.max(bmp.width, bmp.height);
				if (longest <= IMAGE_MAX_EDGE) { return grmailReadAsDataURL(file); }
				var scale = IMAGE_MAX_EDGE / longest;
				var w = Math.max(1, Math.round(bmp.width * scale));
				var h = Math.max(1, Math.round(bmp.height * scale));
				var canvas = document.createElement("canvas");
				canvas.width = w;
				canvas.height = h;
				canvas.getContext("2d").drawImage(bmp, 0, 0, w, h);
				var type = file.type === "image/png" ? "image/png" : "image/jpeg";
				return new Promise(function (resolve) {
					canvas.toBlob(function (out) {
						resolve(out ? grmailReadAsDataURL(out) : grmailReadAsDataURL(file));
					}, type, JPEG_QUALITY);
				});
			}).catch(function () {
				return grmailReadAsDataURL(file);
			}).then(function (result) {
				if (bitmap && bitmap.close) { bitmap.close(); }
				return result;
			});
		} catch (err) {
			return grmailReadAsDataURL(file);
		}
	}

	/* ───────────────────────── 全屏 ───────────────────────── */

	function grmailComposeFullscreen() {
		var container = page();
		var btn = $("fullscreen-btn");
		if (!container || !btn) { return; }
		if (!document.fullscreenElement) {
			if (!container.requestFullscreen) { return; }
			container.requestFullscreen().then(function () {
				btn.textContent = btn.getAttribute("data-exit") || btn.textContent;
			}).catch(function () { });
			return;
		}
		document.exitFullscreen().then(function () {
			btn.textContent = btn.getAttribute("data-enter") || btn.textContent;
		}).catch(function () { });
	}

	/* ───────────────────────── CSV 地址导入 ───────────────────────── */

	function renderCsvError(msg) {
		var host = $("csv-result");
		if (!host) { return; }
		var p = document.createElement("p");
		p.className = "error";
		p.setAttribute("role", "alert");
		p.textContent = msg || pageData("csvErr", "CSV parse failed");
		host.replaceChildren(p);
	}

	function grmailCsvImport() {
		var input = $("csv-file");
		var form = $("compose-form");
		var host = $("csv-result");
		if (!input || !form || !host || !input.files || input.files.length === 0) { return; }
		var token = form.querySelector("input[name=csrf_token]");
		if (!token) { return; }
		var fd = new FormData();
		fd.append("csrf_token", token.value);
		fd.append("file", input.files[0]);

		fetch("/compose/csv-import", { method: "POST", body: fd, credentials: "same-origin" })
			.then(function (res) { return res.ok ? res.text() : Promise.reject(res.status); })
			.then(function (html) {
				// 服务端返回同源可信片段：解析后按节点替换，避免字符串直接注入。
				var doc = new DOMParser().parseFromString("<div>" + html + "</div>", "text/html");
				var root = doc.body.firstChild;
				if (!root) { renderCsvError(""); return; }
				host.replaceChildren.apply(host, Array.prototype.slice.call(root.childNodes));
				var text = host.textContent.trim();
				if (text) { window.grmailShowToast(text.slice(0, 80), "ok"); }
			})
			.catch(function () { renderCsvError(""); });
	}

	function grmailCsvMerge() {
		var target = $("csv-target");
		if (!target) { return; }
		var boxes = document.querySelectorAll("#csv-result input.csv-addr:checked");
		if (boxes.length === 0) { return; }
		var addrs = Array.prototype.map.call(boxes, function (b) { return b.value; });
		var dest = $(target.value);
		if (!dest) { return; }
		var current = dest.value.trim();
		dest.value = current ? current + ", " + addrs.join(", ") : addrs.join(", ");
	}

	/* ───────────────────────── 提交 ───────────────────────── */

	var grmailSubmitAction = "";

	function bindSubmit() {
		var form = $("compose-form");
		if (!form) { return; }

		form.addEventListener("click", function (e) {
			var btn = e.target.closest && e.target.closest("button[type=submit][name=action]");
			if (btn) { grmailSubmitAction = btn.value; }
		}, true);

		form.addEventListener("submit", function () {
			grmailComposeSync();
			// 动态隐藏域：按钮在提交期被禁用后不进入表单数据集，故此域承载 action。
			var h = document.createElement("input");
			h.type = "hidden";
			h.name = 'action';
			h.value = grmailSubmitAction || "save_draft";
			form.appendChild(h);

			var btns = form.querySelectorAll("button[type=submit]");
			for (var i = 0; i < btns.length; i++) { btns[i].disabled = true; }
		});
	}

	/* ───────────────────────── 附件预检 ───────────────────────── */

	function bindAttachments() {
		var input = document.querySelector('#compose-form input[name="attachments"]');
		if (!input) { return; }
		input.addEventListener("change", function () {
			var names = $("attach-names");
			var total = 0;
			for (var i = 0; i < input.files.length; i++) { total += input.files[i].size; }

			if (names) {
				if (input.files.length === 0) { names.textContent = ""; }
				else if (input.files.length === 1) { names.textContent = input.files[0].name; }
				else { names.textContent = input.files.length + pageData("filesFmt", " files selected"); }
			}
			if (total > ATTACH_LIMIT) {
				window.grmailShowToast(pageData("attachErr", "") || "Attachments exceed limit (35MiB)", "err");
				input.value = "";
				if (names) { names.textContent = ""; }
			}
		});
	}

	/* ───────────────────────── 收件人提示 ───────────────────────── */

	function looksInvalid(value) {
		var parts = value.split(",");
		for (var i = 0; i < parts.length; i++) {
			var s = parts[i].trim();
			if (!s) { continue; }
			var at = s.indexOf("@");
			if (at <= 0 || at === s.length - 1 || /\s/.test(s)) { return true; }
		}
		return false;
	}

	function bindRecipientHints() {
		["f-to", "f-cc", "f-bcc"].forEach(function (id) {
			var el = $(id);
			if (!el) { return; }
			el.addEventListener("blur", function () {
				var hintId = id + "-hint";
				var old = $(hintId);
				if (old) { old.remove(); }
				var value = el.value.trim();
				if (value === "" || !looksInvalid(value)) { return; }
				var label = el.closest("label");
				if (!label) { return; }
				var p = document.createElement("p");
				p.id = hintId;
				p.className = "hint";
				p.setAttribute("role", "status");
				p.textContent = pageData("rcptErr", "") || "Recipient address format may be invalid";
				label.appendChild(p);
			});
		});
	}

	/* ───────────────────────── 快捷键提示 ───────────────────────── */

	function grmailAdaptShortcutTitles() {
		if (!/Mac|iPhone|iPad/.test(navigator.platform || "")) { return; }
		document.querySelectorAll('#compose-toolbar button[title*="(Ctrl+"]').forEach(function (btn) {
			btn.title = btn.title.replace(/\(Ctrl\+([A-Z])\)/g, "(⌘$1)");
		});
	}

	/* ───────────────────────── 初始化 ───────────────────────── */

	function init() {
		grmailEditorInit();
		grmailAdaptShortcutTitles();
		bindSubmit();
		bindAttachments();
		bindRecipientHints();

		var parseBtn = $("csv-parse-btn");
		if (parseBtn) { parseBtn.addEventListener("click", grmailCsvImport); }

		var fullBtn = $("fullscreen-btn");
		if (fullBtn) { fullBtn.addEventListener("click", grmailComposeFullscreen); }

		var csvResult = $("csv-result");
		if (csvResult) {
			csvResult.addEventListener("click", function (e) {
				if (e.target && e.target.id === "csv-merge-btn") { grmailCsvMerge(); }
			});
		}

		document.addEventListener("fullscreenchange", function () {
			var btn = $("fullscreen-btn");
			if (!btn) { return; }
			btn.textContent = document.fullscreenElement
				? btn.getAttribute("data-exit")
				: btn.getAttribute("data-enter");
		});
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", init);
	} else {
		init();
	}
})();
