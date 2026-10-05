// U12 Web 侧 Sieve 编辑器缺口修复集成测试（Sieve编辑器缺口修复批次——计划书步骤 3；
// NFR-015 全离线：httptest+临时 SQLite 库，复用 u9Env 基建）。
// 覆盖：#30 新建全链（new 表单名称输入→表单名优先保存→列表可见→回读一致→编辑态只读）、
// #30 非法名拒绝（保留名/空名/路径字符/超长——重渲染保持输入框）、
// #31 取消激活（激活目标清除→无激活态、非激活目标幂等且不误清他脚本激活、不存在 404）。
// 修改历史：
//
//	2026-10-04 22:05:00 | 新建 | Sieve编辑器缺口修复批次（G2 批准 2026-10-04 21:56:23）
package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"GRmail/internal/storage"
)

// newSieveWebTestEnv 复用 u9Env 基建并注入 Sieve 仓储（sieveScripts 为 Server 私有字段，
// 构造后赋值即生效——handler 运行时读取；u9Env 原构造不注入=503 渐进态语义保持零侵入）。
func newSieveWebTestEnv(t *testing.T) (*u9Env, storage.SieveScriptRepo) {
	t.Helper()
	env := newU9Env(t)
	scripts := storage.NewSQLiteSieveScriptRepo(env.rawDB)
	env.srv.sieveScripts = scripts
	return env, scripts
}

// TestSieveWebNewScriptLifecycle #30 新建全链：GET new 表单（名称输入框+新建标题）→
// POST 表单名优先于 URL 参数保存 → 列表可见 → 编辑页回读一致且名称只读（无输入框）。
func TestSieveWebNewScriptLifecycle(t *testing.T) {
	env, _ := newSieveWebTestEnv(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf1")

	// 1. GET /sieve/new：名称输入框（required）+新建标题（zh 缺省）+非编辑态标题
	res := env.get(t, "/sieve/new", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /sieve/new 期望 200 得 %d", res.StatusCode)
	}
	body := bodyOf(t, res)
	if !strings.Contains(body, `name="name"`) {
		t.Error("new 态应渲染名称输入框（name=\"name\"）")
	}
	if !strings.Contains(body, "required") {
		t.Error("名称输入框应为必填（required）")
	}
	if !strings.Contains(body, "新建脚本") {
		t.Error("new 态标题应为「新建脚本」")
	}
	if strings.Contains(body, "编辑脚本：") {
		t.Error("new 态不应渲染编辑态标题")
	}

	// 2. POST /sieve/new：表单 name=hello（URL 参数为 new——表单名优先）
	res = env.postForm(t, "/sieve/new", cookie, "csrf1", map[string][]string{
		"name":    {"hello"},
		"content": {"keep;"},
	})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /sieve/new 期望 303 得 %d（正文：%s）", res.StatusCode, bodyOf(t, res))
	}

	// 3. 列表可见 hello
	res = env.get(t, "/sieve", cookie)
	body = bodyOf(t, res)
	if !strings.Contains(body, "hello") {
		t.Error("保存后列表应含脚本 hello")
	}

	// 4. 编辑页回读一致+名称只读（无名称输入框）
	res = env.get(t, "/sieve/hello", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /sieve/hello 期望 200 得 %d", res.StatusCode)
	}
	body = bodyOf(t, res)
	if !strings.Contains(body, "keep;") {
		t.Error("编辑页应回读脚本内容 keep;")
	}
	// D3 B 形态（2026-10-05 侧栏交互缺陷修复批次）：全站侧栏「管理文件夹」创建表单
	// 含 name="name" 输入框（mail_list.templ 侧栏组件）——断言收窄至脚本名输入框特征
	// 形态（maxlength="128"——#30 脚本名输入框专属，侧栏创建框无此属性）
	if strings.Contains(body, `name="name" maxlength="128"`) {
		t.Error("编辑态（既有脚本）不应渲染脚本名输入框")
	}
}

// TestSieveWebNewScriptInvalidName #30 非法名拒绝：保留路由名 new、空名、路径分隔与
// 查询锚点字符、超长——全部 400 重渲染且名称输入框保持（不消失）。
func TestSieveWebNewScriptInvalidName(t *testing.T) {
	env, scripts := newSieveWebTestEnv(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf2")

	cases := []struct {
		label string
		name  string
	}{
		{"保留路由名 new", "new"},
		{"空名", ""},
		{"路径分隔符", "a/b"},
		{"查询锚点", "a?b"},
		{"超长128", strings.Repeat("x", 129)},
	}
	for _, tc := range cases {
		res := env.postForm(t, "/sieve/new", cookie, "csrf2", map[string][]string{
			"name":    {tc.name},
			"content": {"keep;"},
		})
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("[%s] 期望 400 得 %d", tc.label, res.StatusCode)
			continue
		}
		body := bodyOf(t, res)
		if !strings.Contains(body, `name="name"`) {
			t.Errorf("[%s] 400 重渲染应保持名称输入框", tc.label)
		}
		if !strings.Contains(body, "脚本名无效") {
			t.Errorf("[%s] 应呈现「脚本名无效」错误文案", tc.label)
		}
	}

	// 拒绝后零落库
	list, err := scripts.ListScripts(context.Background(), env.mailbox.ID)
	if err != nil {
		t.Fatalf("ListScripts: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("非法名全部拒绝后不应有脚本落库，得 %d 条", len(list))
	}
}

// TestSieveWebDeactivate #31 取消激活：激活目标清除（无激活态恢复）、非激活目标幂等
// 且不误清他脚本激活态（GetActiveScript 名比对防线）、不存在 404、列表激活行按钮呈现。
func TestSieveWebDeactivate(t *testing.T) {
	env, scripts := newSieveWebTestEnv(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf3")
	ctx := context.Background()

	// 直造两脚本 a/b 并激活 a（repo 层语义 U12b 已覆盖——此处 Web 链前置态）
	for _, name := range []string{"a", "b"} {
		if err := scripts.PutScript(ctx, &storage.SieveScript{
			MailboxID: env.mailbox.ID, Name: name, Content: "keep;",
		}); err != nil {
			t.Fatalf("PutScript %s: %v", name, err)
		}
	}
	if err := scripts.SetActive(ctx, env.mailbox.ID, "a"); err != nil {
		t.Fatalf("SetActive a: %v", err)
	}

	// 1. 非激活目标 b 的 deactivate=幂等 303，且不得误清 a 的激活（名比对防线）
	res := env.postForm(t, "/sieve/b/deactivate", cookie, "csrf3", nil)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("非激活目标 deactivate 期望幂等 303 得 %d", res.StatusCode)
	}
	if act, err := scripts.GetActiveScript(ctx, env.mailbox.ID); err != nil || act == nil || act.Name != "a" {
		t.Errorf("非激活目标 deactivate 后 a 应保持激活，得 (%v, %v)", act, err)
	}

	// 2. 列表：激活行 a 呈现「取消激活」按钮、非激活行 b 呈现「激活」按钮
	res = env.get(t, "/sieve", cookie)
	body := bodyOf(t, res)
	if !strings.Contains(body, "/sieve/a/deactivate") || !strings.Contains(body, "取消激活") {
		t.Error("激活行应呈现取消激活表单/按钮")
	}
	if strings.Contains(body, "/sieve/b/deactivate") {
		t.Error("非激活行不应有取消激活按钮")
	}
	if !strings.Contains(body, "/sieve/b/activate") {
		t.Error("非激活行应保持激活按钮")
	}

	// 3. 激活目标 a 的 deactivate→303→无激活态恢复（ErrNoActiveScript）
	res = env.postForm(t, "/sieve/a/deactivate", cookie, "csrf3", nil)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("deactivate a 期望 303 得 %d", res.StatusCode)
	}
	if _, err := scripts.GetActiveScript(ctx, env.mailbox.ID); !errors.Is(err, storage.ErrNoActiveScript) {
		t.Errorf("取消激活后应无激活脚本，得 %v", err)
	}

	// 4. 不存在脚本 deactivate→404
	res = env.postForm(t, "/sieve/ghost/deactivate", cookie, "csrf3", nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("不存在脚本 deactivate 期望 404 得 %d", res.StatusCode)
	}
}
